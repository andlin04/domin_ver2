# Third-party notices

domin itself is MIT-licensed ([LICENSE](LICENSE)). This file lists what it ships from others, what it runs without
shipping, and the data it uses.

## 1. Shipped in this repository

| File | Name, version | License | Source |
| --- | --- | --- | --- |
| `domin/static/vendor/chart.umd.min.js` | Chart.js 4.4.1 | MIT | https://www.chartjs.org, https://github.com/chartjs/Chart.js |
| `domin/static/world.json` | Natural Earth 1:110m countries (simplified, reduced to name, keys and rings) | Public domain | https://www.naturalearthdata.com |

`domin/static/backdrop.svg`, `favicon.svg`, `app.css`, `app.js` and the other static files are domin's own (MIT). The
UI uses system fonts only; no font files are shipped. PDF reports use fpdf2's built-in core fonts (no embedded font
files).

### Chart.js (MIT)
```
The MIT License (MIT)

Copyright (c) 2014-2022 Chart.js Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```
The vendored file carries the upstream banner (`Chart.js v4.4.1 ... (c) 2023 Chart.js Contributors, Released under the
MIT License`).

### Natural Earth
"All versions of Natural Earth raster + vector map data found on this website are in the public domain." No
attribution required (https://www.naturalearthdata.com/about/terms-of-use/).

## 2. Run, not shipped
Installed by `deploy/install.sh` from the distribution or upstream, or by the user; each keeps its own license. domin
starts them as separate programs (subprocesses or system services) and does not link or bundle them.

| Program | Used for | License | Installed by |
| --- | --- | --- | --- |
| nmap | posture scans, nmap discovery | Nmap Public Source License (NPSL), https://nmap.org/npsl/ | apt (posture component) |
| amass v3.23.3 | passive and active subdomain discovery | Apache-2.0 | install.sh downloads the pinned release from GitHub (SHA-256 checked) |
| tor | Tor route | BSD-3-Clause (The Tor Project) | apt (posture component), off by default |
| wireguard-tools (`wg`, `wg-quick`) | Mullvad route (a WireGuard tunnel) | GPL-2.0 | apt (posture component) |
| proxychains4 | proxy routes for nmap | GPL-2.0 | apt |
| nginx | TLS, rate limits, reverse proxy | BSD-2-Clause | apt |
| certbot | Let's Encrypt certificates (public mode with `--email`) | Apache-2.0 | apt |
| SQLite | database (through Python's `sqlite3`) | Public domain | Python / apt |
| Python packages ([deploy/requirements.txt](deploy/requirements.txt)) | the app | each its own: e.g. FastAPI, pydantic MIT; Starlette, uvicorn, httpx BSD-3-Clause; Jinja2, segno BSD; dnspython ISC; cryptography Apache-2.0 or BSD-3-Clause; fpdf2 LGPL-3.0; pycountry LGPL-2.1 | pip, pinned with hashes |

Mullvad is a third-party VPN service; using the Mullvad route needs your own Mullvad account and follows Mullvad's
terms.

## 3. Data sources

| Source | Used for | Terms |
| --- | --- | --- |
| DB-IP IP to Country Lite | countries of addresses, visitors and sign-ins | CC BY 4.0, attribution required: every page footer shows "IP Geolocation by DB-IP" linking to https://db-ip.com |
| NVD (NIST) CVE API | CVE details matched by CPE | NVD terms of use; the CVE look-up page states: "This product uses the NVD API but is not endorsed or certified by the NVD." |
| OSV.dev | CVEs for packages | Records keep the license of their source database (e.g. GitHub Advisory Database CC BY 4.0, Ubuntu CC BY-SA 4.0), https://google.github.io/osv.dev/data/; each finding links to its OSV/NVD record |
| crt.sh (certificate transparency) | host name discovery | public service, queried live; no data shipped |
| RDAP (registries, rdap.org) | ASN, prefix, network name, registration data | public service, queried live; no data shipped |
| Public DNS resolvers (`domin/resolvers.txt`, e.g. Cloudflare 1.1.1.1, Google 8.8.8.8, Quad9 DoH) | DNS lookups | addresses only, queried live |
