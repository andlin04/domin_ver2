"""Security posture (stage 2): fingerprint the in-scope addresses of an inventoried domain and match their
services against the CVE layer.

Stage 1 (the inventory scan) finds a domain's host names and addresses. A posture scan takes the addresses of the
domain's latest inventory scan, keeps those inside the posture scope (Settings: IP and country rules), and
fingerprints each one (:func:`fingerprint.scan`). An analyst starts it from the Security page, for the whole domain
or one host name; nothing starts it automatically.

Every scan is one row in posture_scans per address. The web app only queues rows; the worker's posture thread runs
them one at a time, so the web process never probes a target. The latest finished row per (domain, address) is the
current posture; older rows stay as history.
"""
from __future__ import annotations

import json
import logging
import re
import sqlite3
from datetime import datetime, timedelta

import httpx

from . import admin, cve, db, fingerprint, proxy, tags, users

log = logging.getLogger("domin.posture")


def targets(conn: sqlite3.Connection, domain: str, host: str = "", ip: str = "",
            names: set[str] | None = None) -> tuple[list[dict], int]:
    """Addresses of the domain's latest inventory scan inside the posture scope, as [{ip, hosts, country}], and how
    many addresses the scope or the "Never scan" exclusions left out. host, ip or names (a set of host names) narrow
    the set. An address is skipped when every host name on it is excluded."""
    scope = users.get_scope(conn)
    rows = conn.execute(f"""SELECT r.host, r.ip, r.country, r.asn, r.netname, r.descr FROM records r
                            JOIN ({db.LATEST}) s ON s.id = r.scan_id
                            JOIN domains d ON d.id = s.domain_id WHERE d.name = ? AND r.ip != ''""", (domain,))
    by_ip: dict[str, dict] = {}
    for r in rows:
        if (host and r["host"] != host) or (ip and r["ip"] != ip) or (names is not None and r["host"] not in names):
            continue
        e = by_ip.setdefault(r["ip"], {"ip": r["ip"], "hosts": set(), "country": r["country"] or ""})
        if not users.excluded(scope["posture_exclude"], r["host"], users.owner_text(r)):
            e["hosts"].add(r["host"])
    keep = [{**e, "hosts": sorted(e["hosts"])} for e in by_ip.values()
            if e["hosts"] and users.posture_ok(scope, e["ip"], e["country"])]
    keep.sort(key=lambda e: e["ip"])
    return keep, len(by_ip) - len(keep)


_PROFILE_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")
DEFAULT_PROFILE = "default"


def profiles(conn: sqlite3.Connection) -> list[dict]:
    return [dict(r) for r in conn.execute("SELECT * FROM posture_profiles ORDER BY name != 'default', name")]


def profile(conn: sqlite3.Connection, name: str) -> dict | None:
    row = conn.execute("SELECT * FROM posture_profiles WHERE name = ?", (name,)).fetchone()
    return dict(row) if row else None


def check_profile(name: str, ports: str, intensity, timing, timeout, route: str = "",
                  routes: set[str] = frozenset()) -> tuple[dict | None, str]:
    """Validate a profile form; returns (profile, "") or (None, error). route: '' (Default: the default route),
    'direct' or one of the route ids in routes."""
    if not _PROFILE_NAME.match(name or ""):
        return None, "Name: 1-40 lower-case letters, digits, - or _."
    if not fingerprint.valid_ports(ports):
        return None, "Ports: digits, commas and hyphens only (e.g. 22,80,443 or 1-1024)."
    try:
        intensity, timing, timeout = int(intensity), int(timing), int(timeout)
    except (TypeError, ValueError):
        return None, "Intensity, timing and timeout must be whole numbers."
    if not (0 <= intensity <= 9 and 1 <= timing <= 4 and 10 <= timeout <= 900):
        return None, "Intensity 0-9, timing 1-4, timeout 10-900 seconds."
    if route not in ("", proxy.DIRECT, *routes):
        return None, "Route: pick one from the list."
    return {"name": name, "ports": ports, "intensity": intensity, "timing": timing, "timeout": timeout,
            "route": route}, ""


def save_profile(conn: sqlite3.Connection, p: dict, note: str, by: str) -> None:
    conn.execute("""INSERT INTO posture_profiles (name, ports, intensity, timing, timeout, route, note, updated,
                    updated_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(name) DO UPDATE SET
                    ports = excluded.ports, intensity = excluded.intensity, timing = excluded.timing,
                    timeout = excluded.timeout, route = excluded.route, note = excluded.note,
                    updated = excluded.updated, updated_by = excluded.updated_by""",
                 (p["name"], p["ports"], p["intensity"], p["timing"], p["timeout"], p.get("route", ""), note[:200],
                  db.now(), by))


def delete_profile(conn: sqlite3.Connection, name: str) -> bool:
    """The default profile stays; past scans keep their recorded parameters."""
    if name == DEFAULT_PROFILE:
        return False
    return conn.execute("DELETE FROM posture_profiles WHERE name = ?", (name,)).rowcount > 0


def enqueue(conn: sqlite3.Connection, domain: str, found: list[dict], prof: dict | str, requested_by: str,
            batch: list[int] | None = None) -> int:
    """Queue one posture scan per address with the profile's parameters (prof: name, ports, intensity, timing,
    timeout, route; a bare port list means the default knobs and route); an address already queued or running for
    the domain is left alone. Returns how many were queued. batch, when given, gets the row id per address (new or
    already pending): the set the progress dialog follows."""
    if isinstance(prof, str):
        prof = {"name": "", "ports": prof, "intensity": 2, "timing": 3, "timeout": 120, "route": ""}
    n = 0
    for t in found:
        row = conn.execute("""SELECT id FROM posture_scans WHERE domain = ? AND ip = ?
                              AND status IN ('queued', 'running')""", (domain, t["ip"])).fetchone()
        if row:
            if batch is not None:
                batch.append(row["id"])
            continue
        cur = conn.execute("""INSERT INTO posture_scans (domain, ip, hosts, country, ports, status, requested_by,
                              created, profile, intensity, timing, timeout, route) VALUES (?, ?, ?, ?, ?, 'queued',
                              ?, ?, ?, ?, ?, ?, ?)""",
                           (domain, t["ip"], ",".join(t["hosts"]), t["country"], prof["ports"], requested_by,
                            db.now(), prof["name"], prof["intensity"], prof["timing"], prof["timeout"],
                            prof.get("route") or ""))
        if batch is not None:
            batch.append(cur.lastrowid)
        n += 1
    return n


def pending_ids(conn: sqlite3.Connection, domain: str = "") -> list[int]:
    """Ids of the queued and running rows (of one domain, or all)."""
    where, args = ("AND domain = ?", (domain,)) if domain else ("", ())
    return [r[0] for r in conn.execute(f"SELECT id FROM posture_scans WHERE status IN ('queued', 'running') {where} "
                                       "ORDER BY id", args)]


def recent_ids(conn: sqlite3.Connection, domain: str = "", hours: int = 24, limit: int = 5000) -> list[int]:
    """Ids for the Scans tab's activity board: queued and running rows plus those finished in the last `hours`."""
    since = (datetime.now() - timedelta(hours=hours)).isoformat(timespec="seconds")
    where, args = ("AND domain = ?", (domain,)) if domain else ("", ())
    return [r[0] for r in conn.execute(
        f"""SELECT id FROM posture_scans WHERE (status IN ('queued', 'running') OR finished >= ?) {where}
            ORDER BY id DESC LIMIT ?""", (since, *args, limit))][::-1]


def _worst(services: list[dict]) -> str:
    sevs = {f["severity"] for s in services for f in s.get("findings") or []}
    return next((x for x in SEVERITIES if x in sevs), "none")


def progress(conn: sqlite3.Connection, ids: list[int]) -> dict:
    """Progress of a set of posture_scans rows (one request's batch) for the progress dialog: counts, the addresses
    running now, seconds since the first was queued, and one item per row with its result."""
    rows = [dict(r) for r in conn.execute(
        f"""SELECT id, domain, ip, hosts, status, created, started, finished, services, open_ports, cves, high, error,
                   chunks, chunks_done FROM posture_scans WHERE id IN ({",".join("?" * len(ids))}) ORDER BY id""",
        ids)] if ids else []
    count = {s: sum(1 for r in rows if r["status"] == s) for s in ("queued", "running", "done", "failed")}
    finished = count["queued"] + count["running"] == 0
    elapsed = 0
    if rows:
        start = datetime.fromisoformat(min(r["created"] for r in rows))
        end = datetime.fromisoformat(max(r["finished"] or "" for r in rows)) if finished else datetime.now()
        elapsed = max(0, int((end - start).total_seconds()))
    items = [{"id": r["id"], "domain": r["domain"], "ip": r["ip"], "host": (r["hosts"] or "").split(",")[0],
              "status": r["status"], "finished": r["finished"] or "", "open_ports": r["open_ports"], "cves": r["cves"],
              "high": r["high"], "error": r["error"] or "", "chunks": r["chunks"], "chunks_done": r["chunks_done"],
              "worst": _worst(json.loads(r["services"] or "[]")) if r["status"] == "done" else ""} for r in rows]
    return {"ids": [r["id"] for r in rows], "total": len(rows), **count, "finished": finished, "elapsed": elapsed,
            "current": [i["host"] or i["ip"] for i in items if i["status"] == "running"], "items": items}


def claim(conn: sqlite3.Connection) -> dict | None:
    row = conn.execute("SELECT * FROM posture_scans WHERE status = 'queued' ORDER BY id LIMIT 1").fetchone()
    if not row:
        return None
    n = conn.execute("UPDATE posture_scans SET status = 'running', started = ? WHERE id = ? AND status = 'queued'",
                     (db.now(), row["id"])).rowcount
    conn.commit()
    return dict(row) if n else None


def _finish(conn: sqlite3.Connection, sid: int, status: str, res: dict) -> None:
    services = res.get("services") or []
    findings = [f for s in services for f in s.get("findings") or []]
    conn.execute("""UPDATE posture_scans SET status = ?, finished = ?, services = ?, open_ports = ?, cves = ?,
                    high = ?, note = ?, error = ?, raw = ?, params = ? WHERE id = ?""",
                 (status, db.now(), json.dumps(services), len(services), len({f["cve"] for f in findings}),
                  len({f["cve"] for f in findings if f["severity"] in ("critical", "high")}),
                  res.get("note") or "", res.get("error") or "", res.get("raw") or "", res.get("params") or "", sid))


RAW_KEY = "worker:raw"   # kv: "1" when the worker last found it may send raw packets (fingerprint.raw_capable)


def run(conn: sqlite3.Connection, row: dict, cve_db: cve.Database, client: httpx.Client | None,
        api_key: str = "") -> None:
    """Run one claimed row. The scope is checked again: it may have changed while the row waited."""
    scope = users.get_scope(conn)
    if not users.posture_ok(scope, row["ip"], row["country"]):
        _finish(conn, row["id"], "failed", {"error": "outside the posture scope (Settings changed after queueing)"})
        return
    able = fingerprint.raw_capable()
    admin.kv_set(conn, RAW_KEY, "1" if able else "0")   # Settings shows whether the worker can send raw packets
    raw = scope["raw_scans"] and able
    cfg = proxy.get(conn)   # read per scan: a change on the Routes page applies to the next one
    r = None
    try:   # the profile's route, copied at queueing ('' = the default route as it is now)
        r = proxy.pick(cfg, row.get("route") or "")
        via = proxy.hop(conn, r, row["ip"], row["country"], client)
    except proxy.ProxyError as exc:   # fail closed: never a direct scan instead (gone, disabled, can't carry it)
        r = r or proxy.find(cfg, row.get("route") or cfg["posture"])
        _finish(conn, row["id"], "failed", {"error": f"route: {exc}",
                                            "params": f"via {proxy.describe(r) or 'a deleted route'}"})
        log.info("posture %s %s: route: %s", row["domain"], row["ip"], exc)
        return
    def saved(p: dict) -> None:   # each finished chunk is the resume point; progress clears the requeue mark
        conn.execute("UPDATE posture_scans SET chunks = ?, chunks_done = ?, services = ?, open_ports = ?, raw = ?, "
                     "note = '' WHERE id = ?", (p["chunks"], p["chunks_done"], json.dumps(p["services"]),
                                                len(p["services"]), p["raw"], row["id"]))
        conn.commit()

    resume = {"chunks_done": row.get("chunks_done") or 0, "services": json.loads(row.get("services") or "[]"),
              "raw": row.get("raw") or ""}
    conn.commit()   # the writes above (raw flag, route) must not hold the write lock for the minutes nmap runs
    try:
        with proxy.cve_client(proxy.cve_hop(conn, cfg, r, via, client), client) as lookups:
            res = fingerprint.scan(row["ip"], cve_db=cve_db, client=lookups, api_key=api_key, ports=row["ports"],
                                   display=row["hosts"].split(",")[0] or row["ip"],
                                   intensity=row.get("intensity", 2), timing=row.get("timing", 3),
                                   timeout=row.get("timeout", 120), via=via, resume=resume, on_chunk=saved,
                                   raw=raw)
    except Exception as exc:   # one bad host must not stop the queue
        log.exception("posture scan %s failed", row["ip"])
        res = {"error": f"internal error ({type(exc).__name__})"}
    _finish(conn, row["id"], "failed" if res.get("error") else "done", res)
    log.info("posture %s %s: %s", row["domain"], row["ip"], res.get("error") or "done")


def refresh_fixes(conn: sqlite3.Connection, cve_db: cve.Database, client: httpx.Client | None,
                  api_key: str = "") -> dict:
    """Bring the fixed versions of stored findings up to date from a fresh CVE look-up of the same CPEs (findings
    stored before NVD ranges were read, or read less precisely). Only the `fixed` field changes: which CVEs a scan
    found stays as it was, so the Changes panel keeps its history. Returns {scans, findings} updated."""
    lookups: dict[str, dict] = {}
    scans = updated = 0
    for r in conn.execute("SELECT id, services FROM posture_scans WHERE status = 'done' AND cves > 0").fetchall():
        services, n = json.loads(r["services"] or "[]"), 0
        for s in services:
            if not s.get("findings"):
                continue
            fixed: dict[str, str] = {}
            for t in (a for c in s.get("cpes") or [] if (p := fingerprint.parse_cpe(c))
                      for a in fingerprint.with_aliases(p)):
                key = cve.target_key(t)
                if key not in lookups:
                    lookups[key] = cve.lookup(cve_db, t, client, api_key)
                fixed.update({f["cve"]: f["fixed"] for f in lookups[key]["findings"] if f.get("fixed")})
            for f in s.get("findings") or []:
                if fixed.get(f["cve"]) and f.get("fixed") != fixed[f["cve"]]:
                    f["fixed"] = fixed[f["cve"]]
                    n += 1
        if n:
            conn.execute("UPDATE posture_scans SET services = ? WHERE id = ?", (json.dumps(services), r["id"]))
            conn.commit()
            scans, updated = scans + 1, updated + n
    return {"scans": scans, "findings": updated}


def refresh_cves(conn: sqlite3.Connection, cve_db: cve.Database, client: httpx.Client | None,
                 api_key: str = "") -> dict:
    """Match the latest successful scan of every address against the current CVE data again (newly published CVEs,
    fixed versions, scores); the services found stay as scanned. Older scans keep the CVEs of their day, so the
    Changes panel shows a CVE published since the previous scan as new. Returns {scans, changed}."""
    rows = conn.execute("""SELECT id, services FROM posture_scans p WHERE status = 'done' AND open_ports > 0
                           AND id = (SELECT max(id) FROM posture_scans q WHERE q.domain = p.domain AND q.ip = p.ip
                                     AND q.status = 'done')""").fetchall()
    lookups: dict[str, dict] = {}
    changed = 0
    for r in rows:
        services = json.loads(r["services"] or "[]")
        before = json.dumps(services, sort_keys=True)
        fingerprint.match(services, cve_db, client, api_key, lookups)
        if json.dumps(services, sort_keys=True) != before:
            findings = [f for s in services for f in s.get("findings") or []]
            conn.execute("UPDATE posture_scans SET services = ?, cves = ?, high = ? WHERE id = ?",
                         (json.dumps(services), len({f["cve"] for f in findings}),
                          len({f["cve"] for f in findings if f["severity"] in ("critical", "high")}), r["id"]))
            conn.commit()
            changed += 1
    return {"scans": len(rows), "changed": changed}


REQUEUED = "requeued after a worker restart"


def requeue_running(conn: sqlite3.Connection) -> int:
    """Rows a crash or restart left running go back to the queue, keep their place and resume after their last
    finished port chunk. A row requeued before that made no progress since fails instead, so a scan that takes the
    worker down cannot loop. Returns how many were requeued."""
    conn.execute("UPDATE posture_scans SET status = 'failed', finished = ?, error = 'worker restarted twice' "
                 "WHERE status = 'running' AND note = ?", (db.now(), REQUEUED))
    return conn.execute("UPDATE posture_scans SET status = 'queued', started = NULL, note = ? "
                        "WHERE status = 'running'", (REQUEUED,)).rowcount


def current(conn: sqlite3.Connection, domain: str = "", limit: int = 500) -> list[dict]:
    """The current posture per (domain, address): the latest finished scan, with `pending` set when a newer scan is
    queued or running. An address with nothing finished yet shows its pending row."""
    where, args = ("WHERE domain = ?", [domain]) if domain else ("", [])
    rows = conn.execute(f"""
        SELECT p.*, (SELECT q.status FROM posture_scans q WHERE q.domain = p.domain AND q.ip = p.ip
                     AND q.status IN ('queued', 'running') ORDER BY q.id DESC LIMIT 1) AS pending
        FROM posture_scans p JOIN (
            SELECT domain, ip, COALESCE(MAX(CASE WHEN status IN ('done', 'failed') THEN id END), MAX(id)) AS id
            FROM posture_scans {where} GROUP BY domain, ip) m ON m.id = p.id
        ORDER BY p.domain, p.high DESC, p.cves DESC, p.ip LIMIT ?""", (*args, limit)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["services"] = json.loads(d["services"] or "[]")
        if d["pending"] == d["status"]:   # the row shown is itself the pending one
            d["pending"] = None
        out.append(d)
    return out


SEVERITIES = ("critical", "high", "medium", "low", "unknown")
STALE_DAYS = 30


def fixes(f: dict) -> list[str]:
    """Fixed versions published for a finding ("fixed" holds them joined by " / "); empty = no fix published yet."""
    return [x.strip() for x in (f.get("fixed") or "").split(" / ") if x.strip()]


def links(f: dict) -> list[tuple[str, str]]:
    """Reference links for a finding: NVD for CVE ids, OSV for other ids, plus the source's own page."""
    vid = f["cve"]
    out = [("NVD", f"https://nvd.nist.gov/vuln/detail/{vid}") if vid.startswith("CVE-")
           else ("OSV", f"https://osv.dev/vulnerability/{vid}")]
    url = f.get("url") or ""
    if url.startswith("https://") and url not in (u for _, u in out):
        out.append(("OSV" if "osv.dev" in url else "NVD" if "nvd.nist.gov" in url else "Source", url))
    return out


def by_service(vulns: list[dict]) -> list[dict]:
    """An address's CVEs grouped per service (product + port), worst group first; a CVE that hits two services
    is listed under both."""
    groups: dict[tuple, dict] = {}
    for v in vulns:   # already worst first, so each group's list is too
        for prod, port, proto in v["where"]:
            g = groups.setdefault((prod, port, proto), {"product": prod, "port": port, "proto": proto, "vulns": []})
            if v not in g["vulns"]:
                g["vulns"].append(v)
    for g in groups.values():
        g["sev_n"] = {x: n for x in SEVERITIES if (n := sum(1 for v in g["vulns"] if v["severity"] == x))}
        g["fixable"] = sum(1 for v in g["vulns"] if v["fixes"])
        g["worst"] = next(iter(g["sev_n"]), "unknown")
    return sorted(groups.values(), key=lambda g: (*(-g["sev_n"].get(s, 0) for s in SEVERITIES), g["port"]))


def report(rows: list[dict], host: str = "") -> dict:
    """Summary of current posture rows for the report: KPIs, chart series and one vulnerability table (each CVE once,
    worst first, with the addresses and host names it affects). Rows gain `worst` (their worst severity, "none" for
    a clean scan, "" when nothing finished), `vulns` (their CVEs once, worst first, with fixes and links), `sev_n`
    and `fixable`. A CVE counts as fixable when a fixed version is published for it. host narrows the rows."""
    if host:
        rows = [r for r in rows if host in (r.get("hosts") or "").split(",")]
    cutoff = (datetime.now() - timedelta(days=STALE_DAYS)).isoformat(timespec="seconds")
    vulns: dict[str, dict] = {}
    services: dict[str, int] = {}
    for r in rows:
        sevs = set()
        own: dict[str, dict] = {}  # this address's CVEs, each once with the product/port pairs it affects
        for s in r["services"]:
            label = s.get("service") or "unknown"
            services[label] = services.get(label, 0) + 1
            prod = f"{s.get('product') or label} {s.get('version') or ''}".strip()
            for f in s.get("findings") or []:
                sevs.add(f["severity"])
                v = vulns.setdefault(f["cve"], {**f, "targets": [], "products": set(), "fixes": fixes(f)})
                tgt = (r["ip"], (r.get("hosts") or "").split(",")[0], s["port"])
                if tgt not in v["targets"]:
                    v["targets"].append(tgt)
                v["products"].add(prod)
                # fixable only when a fixed version is published for every affected product (portal semantics)
                v["fixable"] = v.get("fixable", True) and bool(fixes(f))
                o = own.setdefault(f["cve"], {**f, "where": [], "fixes": fixes(f), "links": links(f)})
                o["where"].append((prod, s["port"], s.get("proto") or "tcp"))
        r["vulns"] = sorted(own.values(), key=lambda v: cve.rank(v["severity"], v["score"]))
        r["by_service"] = by_service(r["vulns"])
        r["sev_n"] = {x: n for x in SEVERITIES if (n := sum(1 for v in r["vulns"] if v["severity"] == x))}
        r["fixable"] = sum(1 for v in r["vulns"] if v["fixes"])
        done = r["status"] == "done"
        r["worst"] = next((x for x in SEVERITIES if x in sevs), "none") if done else ""
        r["stale"] = bool(r.get("finished") and r["finished"] < cutoff)
        # also for scans stored before the flag existed: read from their nmap output
        r["blocked"] = (done and not r["services"] and not r.get("error")
                        and fingerprint.no_answer(r.get("raw") or "", " via " in (r.get("params") or "")))
        if r["blocked"]:
            r["note"] = fingerprint.BLOCKED_NOTE
    table = sorted(vulns.values(), key=lambda v: cve.rank(v["severity"], v["score"]))
    for v in table:
        v["products"] = sorted(v["products"])
        v["addresses"] = list(dict.fromkeys((ip, name) for ip, name, _ in v["targets"]))   # each address once
        v["text"] = " ".join([v["cve"], v["severity"], *v["products"], *v["fixes"],
                              *(x for a in v["addresses"] for x in a if x)]).lower()   # for the Filter box
    rank = {s: i for i, s in enumerate((*SEVERITIES, "none", ""))}
    rows = sorted(rows, key=lambda r: (rank[r["worst"]], -r["high"], -r["cves"], r["ip"]))
    by_sev = {s: sum(1 for v in table if v["severity"] == s) for s in SEVERITIES}
    return {
        "rows": rows, "vulns": table, "by_sev": by_sev,
        "kpi": {"addresses": len(rows), "exposed": sum(1 for r in rows if r["worst"] in ("critical", "high")),
                "cves": len(table), "critical": by_sev["critical"], "high": by_sev["high"],
                "fixable": sum(1 for v in table if v["fixable"]),
                "open_ports": sum(r["open_ports"] for r in rows if r["status"] == "done"),
                "failed": sum(1 for r in rows if r["status"] == "failed"),
                "pending": sum(1 for r in rows if r.get("pending") or r["status"] in ("queued", "running")),
                "stale": sum(1 for r in rows if r["stale"]), "blocked": sum(1 for r in rows if r["blocked"])},
        "charts": {
            # per severity: distinct CVEs an update fixes today vs those still without a published fix
            "fix": [{"label": s, "fix": sum(1 for v in table if v["severity"] == s and v["fixable"]),
                     "nofix": sum(1 for v in table if v["severity"] == s and not v["fixable"])}
                    for s in SEVERITIES if by_sev[s]],
            "services": [{"label": k, "n": n} for k, n in sorted(services.items(), key=lambda x: -x[1])[:8]]},
    }


def anchor(ip: str) -> str:
    """Element id of an address's headline in the report."""
    return "pa-" + ip.replace(":", "-").replace(".", "-")


def domain_summary(rows: list[dict]) -> list[dict]:
    """The all-domains view: one row per domain from report()'s rows (worst first), so the overview lists domains,
    not addresses. Each: domain, worst, rank, sev_n (distinct CVEs per severity), cves, fixable, addresses,
    exposed (addresses with high+), open_ports, blocked, failed, pending, last (newest finished, YYYY-MM-DD HH:MM)."""
    rank = {s: i for i, s in enumerate((*SEVERITIES, "none", ""))}
    out: dict[str, dict] = {}
    for r in rows:
        d = out.setdefault(r["domain"], {"domain": r["domain"], "cve": {}, "fix": set(), "addresses": 0, "exposed": 0,
                                         "open_ports": 0, "blocked": 0, "failed": 0, "pending": 0, "last": "",
                                         "worst": ""})
        d["addresses"] += 1
        d["exposed"] += r["worst"] in ("critical", "high")
        d["open_ports"] += r["open_ports"] if r["status"] == "done" else 0
        d["blocked"] += bool(r["blocked"])
        d["failed"] += r["status"] == "failed"
        d["pending"] += bool(r.get("pending") or r["status"] in ("queued", "running"))
        d["last"] = max(d["last"], (r.get("finished") or "")[:16].replace("T", " "))
        for v in r["vulns"]:
            d["cve"][v["cve"]] = v["severity"]
            if v["fixes"]:
                d["fix"].add(v["cve"])
        if rank[r["worst"]] < rank[d["worst"]]:
            d["worst"] = r["worst"]
    for d in out.values():
        sevs = list(d.pop("cve").values())
        d["sev_n"] = {s: n for s in SEVERITIES if (n := sevs.count(s))}
        d["cves"], d["fixable"], d["rank"] = len(sevs), len(d.pop("fix")), rank[d["worst"]]
    return sorted(out.values(), key=lambda d: (d["rank"], -d["sev_n"].get("critical", 0),
                                               -d["sev_n"].get("high", 0), -d["cves"], d["domain"]))


TREND_DAYS = 90


def trend(conn: sqlite3.Connection, domain: str = "", host: str = "") -> list[dict]:
    """Exposure over time: per day with a finished scan, across the addresses' latest successful scans as of that
    day (the last TREND_DAYS such days): distinct CVEs per severity, open ports and addresses scanned. One day says
    nothing: empty then."""
    where, args = ("AND domain = ?", (domain,)) if domain else ("", ())
    state: dict[tuple[str, str], tuple[dict[str, str], int]] = {}   # (domain, ip) -> ({cve: severity}, open ports)
    days: dict[str, dict] = {}
    for r in conn.execute(f"""SELECT domain, ip, hosts, finished, services FROM posture_scans
                              WHERE status = 'done' AND finished IS NOT NULL {where} ORDER BY finished, id""", args):
        if host and host not in (r["hosts"] or "").split(","):
            continue
        svcs = json.loads(r["services"] or "[]")
        state[(r["domain"], r["ip"])] = ({f["cve"]: f["severity"] for s in svcs for f in s.get("findings") or []},
                                         len(svcs))
        sevs = list({c: sev for found, _ in state.values() for c, sev in found.items()}.values())
        days[r["finished"][:10]] = {"day": r["finished"][:10], **{s: sevs.count(s) for s in SEVERITIES[:4]},
                                    "ports": sum(n for _, n in state.values()), "addresses": len(state)}
    out = list(days.values())[-TREND_DAYS:]
    return out if len(out) > 1 else []


CHANGE_DAYS = 30
CHANGE_ROWS = 100


def port_set(ports: str) -> set[int]:
    """The ports a scan covered ("22,80,1-1024" -> {22, 80, 1..1024})."""
    out: set[int] = set()
    for part in (ports or "").split(","):
        lo, _, hi = part.partition("-")
        if lo.isdigit() and (not hi or hi.isdigit()):
            out.update(range(int(lo), int(hi or lo) + 1))
    return out


def changes(conn: sqlite3.Connection, domain: str = "", host: str = "", now: datetime | None = None) -> dict:
    """What changed between consecutive successful scans of each address: ports opened or closed (only ports both
    scans covered, so a different profile is not a change), service versions, CVEs new or gone. Returns
    {kpi: counts over the last CHANGE_DAYS days, rows: newest first (at most CHANGE_ROWS), compared: addresses
    with two or more scans}."""
    where, args = ("AND domain = ?", (domain,)) if domain else ("", ())
    since = ((now or datetime.now()) - timedelta(days=CHANGE_DAYS)).isoformat(timespec="seconds")
    last: dict[tuple[str, str], dict] = {}
    rows: list[dict] = []
    twice: set[tuple[str, str]] = set()
    for r in conn.execute(f"""SELECT domain, ip, hosts, ports, finished, services FROM posture_scans
                              WHERE status = 'done' AND finished IS NOT NULL {where} ORDER BY finished, id""", args):
        if host and host not in (r["hosts"] or "").split(","):
            continue
        svc = {s["port"]: s for s in json.loads(r["services"] or "[]")}
        cves = {f["cve"]: f["severity"] for s in svc.values() for f in s.get("findings") or []}
        cur = {"ports": port_set(r["ports"]), "svc": svc, "cves": cves}
        prev = last.get((r["domain"], r["ip"]))
        last[(r["domain"], r["ip"])] = cur
        if not prev:
            continue
        twice.add((r["domain"], r["ip"]))
        both = cur["ports"] & prev["ports"]
        base = {"at": r["finished"], "domain": r["domain"], "ip": r["ip"],
                "host": (r["hosts"] or "").split(",")[0] or r["ip"]}

        def ver(s: dict) -> str:
            return " ".join(x for x in (s.get("product"), s.get("version")) if x) or s.get("service") or "?"
        for p in sorted(both & (svc.keys() - prev["svc"].keys())):
            rows.append({**base, "kind": "opened", "detail": f"{p}/tcp {ver(svc[p])}"})
        for p in sorted(both & (prev["svc"].keys() - svc.keys())):
            rows.append({**base, "kind": "closed", "detail": f"{p}/tcp {ver(prev['svc'][p])}"})
        for p in sorted(svc.keys() & prev["svc"].keys()):
            if ver(svc[p]) != ver(prev["svc"][p]):
                rows.append({**base, "kind": "version", "detail": f"{p}/tcp {ver(prev['svc'][p])} → {ver(svc[p])}"})
        for kind, got in (("new-cve", cves.keys() - prev["cves"].keys()),
                          ("gone-cve", prev["cves"].keys() - cves.keys())):
            if got:
                sev = cves if kind == "new-cve" else prev["cves"]
                worst = sorted(got, key=lambda c: (SEVERITIES.index(sev[c]) if sev[c] in SEVERITIES else 9, c))
                rows.append({**base, "kind": kind, "detail": ", ".join(worst[:5]) + (f" +{len(got) - 5}" if
                                                                                   len(got) > 5 else ""),
                             "count": len(got), "severity": sev[worst[0]]})
    recent = [x for x in rows if x["at"] >= since]
    kpi = {k: sum(x.get("count", 1) for x in recent if x["kind"] == k)
           for k in ("opened", "closed", "version", "new-cve", "gone-cve")}
    return {"kpi": kpi, "rows": rows[::-1][:CHANGE_ROWS], "days": CHANGE_DAYS, "compared": len(twice),
            "changed": len({(x["domain"], x["ip"]) for x in recent})}


SEARCH_WORDS = 6


def search_domains(conn: sqlite3.Connection, query: str) -> list[str]:
    """Domains (with a finished inventory scan) whose data holds every word of query, any case: the domain name, the
    latest inventory scan's records (host, address, ASN also as "AS<n>", prefix, network name, description,
    country), the host names' tags, and the latest posture result per address (services json: service, product,
    version, port, CVE ids, severities; note, error). Name order."""
    words = query.lower().split()[:SEARCH_WORDS]
    found: set[str] | None = None
    for w in words:
        like = "%" + w.replace("!", "!!").replace("%", "!%").replace("_", "!_") + "%"
        hit = {r[0] for r in conn.execute(f"""
            SELECT d.name FROM domains d JOIN ({db.LATEST}) s ON s.domain_id = d.id WHERE d.name LIKE :w ESCAPE '!'
            UNION SELECT d.name FROM domains d JOIN ({db.LATEST}) s ON s.domain_id = d.id
              JOIN records r ON r.scan_id = s.id LEFT JOIN host_tags t ON t.host = r.host
              WHERE r.host LIKE :w ESCAPE '!' OR r.ip LIKE :w ESCAPE '!' OR r.asn LIKE :w ESCAPE '!'
                 OR 'as' || r.asn LIKE :w ESCAPE '!' OR r.prefix LIKE :w ESCAPE '!' OR r.netname LIKE :w ESCAPE '!'
                 OR r.descr LIKE :w ESCAPE '!' OR r.country LIKE :w ESCAPE '!' OR t.tag LIKE :w ESCAPE '!'
            UNION SELECT domain FROM posture_scans WHERE id IN
              (SELECT MAX(id) FROM posture_scans WHERE status = 'done' GROUP BY domain, ip)
              AND (services LIKE :w ESCAPE '!' OR note LIKE :w ESCAPE '!' OR error LIKE :w ESCAPE '!')""",
            {"w": like})}
        found = hit if found is None else found & hit
        if not found:
            break
    return sorted(found or ())


def domains(conn: sqlite3.Connection) -> list[str]:
    """Domains with a finished inventory scan, for the target pick-list."""
    return [r[0] for r in conn.execute(f"SELECT d.name FROM domains d JOIN ({db.LATEST}) s ON s.domain_id = d.id "
                                       "ORDER BY d.name")]


def host_list(conn: sqlite3.Connection, domain: str) -> list[dict]:
    """The domain's host names with an address (latest inventory scan), each with its addresses, when a posture scan
    covering it last finished ("" = never), whether one is queued or running now, and `skip`: why a scan would leave
    it out ("out of scope", "on the Never scan list"; "" = it would be scanned)."""
    scope = users.get_scope(conn)
    names: dict[str, dict] = {}
    for r in conn.execute(f"""SELECT r.host, r.ip, r.country, r.asn, r.netname, r.descr FROM records r
                             JOIN ({db.LATEST}) s ON s.id = r.scan_id JOIN domains d ON d.id = s.domain_id
                             WHERE d.name = ? AND r.ip != '' ORDER BY r.host""", (domain,)):
        e = names.setdefault(r["host"], {"host": r["host"], "ips": [], "last": "", "pending": False,
                                         "skip": "out of scope", "countries": []})
        if r["ip"] not in e["ips"]:
            e["ips"].append(r["ip"])
        if r["country"] and r["country"] not in e["countries"]:
            e["countries"].append(r["country"])   # for the Filter box (the map puts a country there)
        if users.excluded(scope["posture_exclude"], r["host"], users.owner_text(r)):
            e["skip"] = e["skip"] if e["skip"] == "" else "on the Never scan list"
        elif users.posture_ok(scope, r["ip"], r["country"] or ""):
            e["skip"] = ""
    for r in conn.execute("SELECT hosts, status, finished FROM posture_scans WHERE domain = ?", (domain,)):
        for h in (r["hosts"] or "").split(","):
            e = names.get(h)
            if not e:
                continue
            if r["status"] in ("queued", "running"):
                e["pending"] = True
            elif r["status"] == "done" and r["finished"] and r["finished"] > e["last"]:
                e["last"] = r["finished"]
    own = tags.for_hosts(conn, list(names))
    for e in names.values():
        e["last"] = e["last"][:16].replace("T", " ")
        e["net_tags"] = users.net_tags(scope["net_tags"], e["ips"])   # Settings > Network tags, for the Filter
        e["tags"] = own.get(e["host"], [])                            # set on the host name (Tags column)
    return list(names.values())


def narrow(conn: sqlite3.Connection, rows: list[dict], domain: str, query: str) -> list[dict]:
    """The report rows the posture page's Filter box leaves (report() rows): all domains = the rows of the domains
    search_domains finds; one domain = the addresses of its host names whose Filter text holds every word."""
    words = query.lower().split()
    if not words:
        return rows
    if not domain:
        keep = set(search_domains(conn, query))
        return [r for r in rows if r["domain"] in keep]
    ips = {ip for h in with_results(host_list(conn, domain), rows) if all(w in h["text"] for w in words)
           for ip in h["ips"]}
    return [r for r in rows if r["ip"] in ips]


def with_results(names: list[dict], rows: list[dict]) -> list[dict]:
    """host_list entries joined with their addresses' current results (report rows): worst severity (`rank`: 0 =
    critical, for sorting), CVEs counted once per host name (`sev_n`, `cves`, `fixable`), open ports, how many of its
    addresses look blocked or failed, and the anchors of the address details."""
    by_ip = {r["ip"]: r for r in rows}
    order = (*SEVERITIES, "none")
    out = []
    for h in names:
        res = [by_ip[ip] for ip in h["ips"] if ip in by_ip]
        cves = {v["cve"]: v for r in res for v in r.get("vulns") or []}
        # what the page's Filter box matches on: names, addresses, services, products, versions, ports, CVEs
        text = [h["host"], *h["ips"], *h.get("countries", []), *h.get("net_tags", []), *h.get("tags", []),
                h.get("skip") or "", *(v["severity"] for v in cves.values()), *cves]
        for r in res:
            text += [r.get("note") or "", r.get("error") or ""]
            for s in r.get("services") or []:
                text += [str(s.get(k) or "") for k in ("service", "product", "version")]
                text.append(f"{s.get('port')}/{s.get('proto') or 'tcp'}")
        # an address shared with another host name was scanned under that name: its result dates this one too
        seen = max(((r.get("finished") or "")[:16].replace("T", " ") for r in res
                    if r.get("status") == "done"), default="")
        worsts = [r["worst"] for r in res if r.get("worst") in order]
        worst = min(worsts, key=order.index) if worsts else ""
        out.append({**h, "last": max(h.get("last") or "", seen), "anchors": [anchor(r["ip"]) for r in res],
                    "worst": worst,
                    "rank": order.index(worst) if worst else len(order),
                    "sev_n": {s: n for s in SEVERITIES if (n := sum(1 for v in cves.values() if v["severity"] == s))},
                    "cves": len(cves), "fixable": sum(1 for v in cves.values() if v["fixes"]),
                    "open_ports": sum(r.get("open_ports") or 0 for r in res),
                    "blocked": sum(1 for r in res if r.get("blocked")), "errors": sum(1 for r in res if r.get("error")),
                    "results": len(res), "text": " ".join(t for t in text if t).lower()})
    return out


def hosts(conn: sqlite3.Connection, domain: str) -> list[str]:
    """Host names with an address in the domain's latest inventory scan, for the host pick-list."""
    return [r[0] for r in conn.execute(f"""SELECT DISTINCT r.host FROM records r JOIN ({db.LATEST}) s
        ON s.id = r.scan_id JOIN domains d ON d.id = s.domain_id WHERE d.name = ? AND r.ip != '' ORDER BY r.host""",
        (domain,))]
