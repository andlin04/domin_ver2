# Features

domin has two components: the **domain inventory** (DNS, public pages by default) and the **security posture**
(port and service scans, CVEs; signed-in pages under `/admin`). Install both or one
([Components](#components)). Screenshots: [gallery](#screenshots). Third-party code, programs and data:
[THIRD-PARTY-NOTICES.md](../THIRD-PARTY-NOTICES.md).

**Contents:** [DNS inventory](#dns-inventory) · [Security posture](#security-posture) ·
[Scheduling and nmap discovery](#scheduling-and-nmap-discovery) · [Routes](#routes-tor-mullvad-proxy) ·
[Scope](#scope) · [Users, roles, two-factor](#users-roles-and-two-factor) · [Sign-in protection](#sign-in-protection) ·
[Syslog](#syslog) · [Reports and export](#reports-and-export) · [CSV import](#csv-import) ·
[Admin dashboard](#admin-dashboard-and-statistics) · [Components](#components) · [Screenshots](#screenshots)

## DNS inventory
Public pages (sign-in can be required, [Sign-in](#users-roles-and-two-factor)). Per domain: host names, addresses,
ASNs, prefixes, countries and hosting providers, and how they change between scans.

- **Scans:** certificate transparency (crt.sh) plus common names, MX and NS; DNS A/AAAA; RDAP for ASN, prefix,
  network name and country. amass when installed. One scan per domain per day, 10 per hour per visitor
  ([limits](CONFIGURATION.md#environment-etcdominenv)).
- **Overview:** totals, scans per day, hosting countries, top providers, EU share per day, recent scan jobs,
  filterable domain table.
- **Domain page:** footprint over time, host names added and removed per scan, countries, providers, EU share over
  time, changes since the previous scan, all records (filter, sort, CSV), compare any two scans.
- **Drilldown (All):** every domain at once (`/all`, also a tab on the overview): host names, addresses, ASNs,
  countries, EU share, charts of countries, providers and ASNs (a bar click filters). Search host, address, ASN,
  prefix, network, description or country, in the latest scans or the whole history (first and last seen). Filters
  narrow figures, charts and table together; CSV download.
  - Filtering runs in the browser on a dataset fetched once (`/data/drill.json`, gzip, cached); without JavaScript the
    same filters run on the server on Enter.
- **Tables:** sort by any column; a filter box per column, the filters add up.
- **Tools:** registration data (RDAP) and e-mail security (MX, SPF, DMARC, MTA-STS, DNSSEC) for one domain.
- **Internal domains (on-prem):** domains under Settings · Internal domains (e.g. `corp.example`) resolve through the
  internal DNS servers only, with no public lookups.
- **Scan API:** `POST /api/scan` (JSON) queues an inventory scan with the visitor limits; private API clients
  (`DOMIN_INTERNAL_IPS`) skip them.

## Security posture
Signed-in pages (`/admin`). Finds services on a domain's addresses and matches them to known CVEs.

- **Posture scans:** nmap service and version detection (`-sV`, TCP connect; SYN scans with `--raw`), one scan per
  address of a domain, queued and run by the worker. Progress and raw nmap output per scan.
- **CVE matching:** fingerprinted products (CPE) are looked up in OSV.dev and NVD; results kept in a local CVE
  database (own, or a shared read-only one). Each finding: severity, CVSS score and vector, description, fixed
  versions, NVD/OSV links. CVE look-up page (Settings · CVE look-up) for a host, a product (vendor, product, version) or a
  package (ecosystem, package, version).
- **Exploit data:** each CVE is marked when it is exploited in the wild (pill **KEV**, CISA catalog, with date added
  and ransomware use), has public exploit code (**exploit**: Exploit-DB, Metasploit, NVD references tagged Exploit)
  or only proof-of-concept repositories (**PoC**: PoC-in-GitHub, labeled unverified third-party code), with the FIRST
  EPSS score. The CVE tables get Exploit (sorts KEV, exploit, PoC, then by EPSS) and EPSS columns and KEV / Exploit /
  PoC chips; a CVE's details and the findings by address list the sources with links (new tab; nothing third-party
  is fetched or shown inline). Downloaded with the daily CVE refresh (or `refresh-exploits`) into the local database;
  pages never call the sources, a failed download keeps the previous data, Settings · CVE look-up shows each
  source's last update and error and turns the feature off. Posture only; every instance keeps its own copy,
  also in shared CVE database mode. Sources and licenses: [THIRD-PARTY-NOTICES.md](../THIRD-PARTY-NOTICES.md).
- **Overview tab (What):** KPIs, CVEs over time (stacked by severity, addresses scanned as a line), fix available or
  not, CVEs found.
- **Analysis tab (Where):** attack surface over time, exposed services (the part with CVEs marked), findings by
  address, hosts and CVEs tables (a CVE id opens its details), changes between scans (ports opened/closed, versions,
  new, fixed and gone CVEs). A search narrows the domain list by host, address, ASN, provider, country, tag, product
  or CVE id.
- **Scans tab:** posture scans and scan activity.
- **Separate areas:** the inventory pages show DNS-scan data only; Posture (top bar, users with the right) holds
  posture results, schedules and nmap discovery, and links back through "View DNS records".
- **Scan profiles:** ports, version intensity, timing, route, note.
- **Host tags:** free labels per host name (suggested from the name); network tags (Settings) tag every host with an
  address in a network.

## Scheduling and nmap discovery
Design detail: [scheduled-scans.md](scheduled-scans.md).

- **nmap discovery (optional):** "Scan with nmap" in Posture · Scans (one domain picked) adds an nmap stage to an
  inventory scan, tuned by a discovery profile (Settings · Discovery profiles: probe method, port check, timing, rate,
  retries, host timeout, reverse DNS, route; the command line is shown). A public domain sweeps only its own
  addresses; an internal domain the hosts of Settings · Internal networks.
- **Scheduled rescans:** per domain, listed and added in Posture · Scans (each user sees the schedules of the domains
  they hold a grant on): an inventory scan with or without a discovery profile and/or posture scans with a profile,
  on all hosts, chosen hosts or a tag; daily, weekly, monthly or every N hours/days, server local time; Run now,
  enable/disable, next and last run; a warning when a posture profile's Tor, Mullvad or proxy route meets private
  addresses.
- **Automatic refreshes:** `DOMIN_REFRESH_DAYS` (or Tuning) re-scans domains whose last scan is older than N days, on
  a separate queue that never delays visitors.

## Routes (Tor, Mullvad, proxy)
Settings · Routes (admin).

- Direct, Tor, Mullvad (WireGuard tunnel, entry country/city), custom proxy (SOCKS5, SOCKS4, HTTP).
- Separate route choice for posture scans, inventory jobs and CVE look-ups; DoH server.
- Tor is installed but off; an admin switches it here (kept across updates). Tor and the Mullvad tunnel are switched
  by root helper units, never by the app ([ARCHITECTURE.md](ARCHITECTURE.md#root-helpers)).
- Internal zones always go direct.

## Scope
- **Posture scope:** CIDR allow/deny, country allow/deny (from the inventory's countries), never-scan exclusions,
  network tags, internal domains.
- **Domain inventory scope:** domain/suffix allow and deny, refused at every entry point.
- **Raw network access** (Settings, with `--raw`): SYN scans and raw-only discovery probes.

## Users, roles and two-factor
Design detail: [delegation.md](delegation.md).

- **Roles:** admin (every domain, users, grants, settings, operations; several allowed, never fewer than one) and
  power user (only the domains granted to it).
- **Grants:** per domain, viewer (reads inventory, posture, CVEs, reports) or maintainer (also posture scans and host
  tags there); a grant covers the domains under it. A maintainer can add viewers to its own domains (Admin menu,
  Domain viewers).
- **Feature rights** per power user: none / read / read-write for Inventory, Posture & CVEs, Scans & schedules, Tags,
  Scan profiles, Discovery profiles.
- **Audit:** changes to users, roles, rights and grants are logged on the Users page.
- **Sign-in:** password, optional two-factor (TOTP with QR code, recovery codes); two-factor can be required per role
  (Settings) and per user (Users, edit page; the user enrols under My account, sent there after sign-in).
- **Sign-in required for** (Settings): Inventory (the public pages) and/or Posture; inventory is open by default,
  posture always needs a session.
- **Admin-set passwords:** admins create users with a password (typed or Generate, with Copy) and hand it over
  themselves; Set password on a user's page resets it and signs that user out. A user may change or keep an
  admin-set password at the next 3 sign-ins; the 4th requires a new one.
- **Header:** every page shows "signed in as <name> (role)" top right and a Log out button; the name opens My account.
- **Sessions:** My account lists your sessions (created, address, country, browser): Sign out one, or Sign out all
  others. Admins see and end a user's sessions on the user's page (Users, Edit).
- **Hidden sign-in link:** `DOMIN_HIDE_SIGNIN_LINK=1` drops the "Sign in" link from the menu; `/admin` still works by
  URL.

## Sign-in protection
Settings > General; each rule on by default, can be turned off.

- **One session per user:** a new sign-in signs that user's other browsers out.
- **New place:** a country not seen for the user in N days (default 90; the /24, or /48 for IPv6, when the country is
  unknown). With two-factor: the code step. Without: refused and waiting for an admin (Users: "Sign-ins waiting for
  approval", Approve or Deny; the user row shows "new place: approve?"). A first sign-in sets the baseline.
- **Impossible travel:** over 900 km/h between the country centroids of the previous and this sign-in (same or
  unknown country: skipped): refused, all the user's sessions end, a new password and two-factor are required.
- **Exempt:** `DOMIN_ADMIN_IPS` and the trusted ranges in Settings (the hit is still logged as "exempt").
- **Break-glass:** the last enabled admin is never blocked, only stepped up (without two-factor it must enrol right
  after the sign-in); `admin-password` still works.
- Every hit is in the audit log (Users, Changes) with user, address, country and rule.
- Countries come from [DB-IP](https://db-ip.com) IP to Country Lite (CC BY 4.0), downloaded by the installer; re-run
  the installer monthly to refresh.

## Syslog
Settings > Logging (admin); off until a server is set.

- Forwards sign-ins, failures, sign-outs, sign-in protection hits and every audit entry (admin changes) as RFC 5424.
- Server: host, port, UDP / TCP / TLS (octet-counted frames; TLS checks the certificate), facility, app-name.
- "Send a test message" sends one harmless message and shows the result.
- Events wait in a bounded queue sent by a background thread; when the server is slow or down they are dropped and
  counted, and the last error shows on the page.

## Reports and export
- **Posture report:** executive and technical report on the ticked host names (or domains) of the posture tables, as
  PDF or Markdown. A table filter unticks the rows it hides, so the report covers the visible ticked rows. With
  exploit data on: KEV / exploit / PoC counts in the summary, an Exploit column with EPSS, and the source links per
  CVE. Sections: summary, recommendations, charts (CVEs and attack surface over time, fixes, services; tables in
  Markdown), top risks, hosts, then one section per host name (facts, services, CVEs, references, what to do; PDF
  bookmarks and links from the host table). A report on one host name is titled and named after it.
- **CSV:** every inventory table, the drilldown and the search results; cells a spreadsheet would run as a formula
  are prefixed with `'`. A CSV export can be imported into another domin ([CSV import](#csv-import)).

## CSV import
- Settings > CSV import (admin, up to 200 MB): a domin CSV export (All records > CSV) or any CSV with a domain or host
  column and some record fields (comma, semicolon or tab separated; UTF-8 or Latin-1).
- A dialog shows the file's columns with sample values and asks which column feeds which field (domain, host, ip, asn,
  prefix, netname, descr, country, last_seen, first_seen, eu), pre-filled from the header names and common aliases
  (hostname/fqdn/name → host, address/ip_address → ip, date/timestamp → last_seen, ...); domin's own export is
  pre-mapped, so you only press Import.
- Only mapped fields are imported; a host without a domain gets its domain from the inventory or the host name.
- The worker imports it in the background; an upload left unmapped is deleted after an hour.
- One imported scan per domain, timed by the file's newest "last seen"; existing scans are kept and importing the
  same file again adds nothing.
- CLI: `import-csv` ([OPERATIONS.md](OPERATIONS.md#commands)).
- Posture only: the same import is under Posture > Import targets; its domains and addresses become posture targets.

## Admin dashboard and statistics
- **Operations:** visits per day, recent visits, usage statistics without stored IP addresses, scan jobs (cancel,
  stop, retry), tuning without restart.
- **Usage statistics:** visitors, page views, visit length and page order, top pages, domains, CSV downloads, tools,
  referrers, countries, scans started and refused; bots counted apart; kept 180 days.
- **Privacy:** no visitor IP addresses stored; a visitor is a hash of address + browser with a daily salt; scan rate
  limits use a salted hash. Signed-in users are the exception: their sessions keep the address, country and browser
  (the session list), and sign-in protection keeps each sign-in's address and country for the new-place days.
- **Tuning** (no restart): pause the worker, once-per-day limit, scans per hour, queue length, lookups per minute,
  max host names per scan, scheduled re-scans, statistics retention, posture scans at once
  ([CONFIGURATION.md](CONFIGURATION.md#tuning-operations-page)).

## Components
- **inventory:** the DNS inventory pages, the public scan API and scheduled refreshes.
- **posture:** security posture and CVEs, scans and schedules, nmap discovery, scan profiles.
- Installed with `install.sh --components` ([INSTALL.md](INSTALL.md#components)); posture brings nmap, Tor,
  wireguard-tools, the Tor/Mullvad root helper units and (`--raw`) the worker's raw sockets.
- **Settings > Components** (admin): one switch per installed component. A component that is not installed is greyed
  out and shows its install command. Off means:
  - its pages and API answer 404, and its menu entries and feature rights are hidden;
  - the worker skips its jobs and its schedules wait;
  - nothing is deleted.

  At least one component stays on. With inventory off, `/` opens Posture.
- **Posture only:** nmap discovery works as before. The CSV import is under **Posture > Import targets**, with the
  same mapping dialog as Settings > CSV import; its domains and addresses become posture targets. No page links to
  DNS records.

## Screenshots
Screenshots of every main view: [README, Screenshots](../README.md#screenshots).
