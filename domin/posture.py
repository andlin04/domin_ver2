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

from . import cve, db, fingerprint, proxy, users

log = logging.getLogger("domin.posture")


def targets(conn: sqlite3.Connection, domain: str, host: str = "", ip: str = "") -> tuple[list[dict], int]:
    """Addresses of the domain's latest inventory scan inside the posture scope, as [{ip, hosts, country}], and how
    many addresses the scope left out. host or ip narrows the set to that host name or address."""
    scope = users.get_scope(conn)
    rows = conn.execute(f"""SELECT r.host, r.ip, r.country FROM records r JOIN ({db.LATEST}) s ON s.id = r.scan_id
                            JOIN domains d ON d.id = s.domain_id WHERE d.name = ? AND r.ip != ''""", (domain,))
    by_ip: dict[str, dict] = {}
    for r in rows:
        if (host and r["host"] != host) or (ip and r["ip"] != ip):
            continue
        e = by_ip.setdefault(r["ip"], {"ip": r["ip"], "hosts": set(), "country": r["country"] or ""})
        e["hosts"].add(r["host"])
    keep = [{**e, "hosts": sorted(e["hosts"])} for e in by_ip.values()
            if users.posture_ok(scope, e["ip"], e["country"])]
    keep.sort(key=lambda e: e["ip"])
    return keep, len(by_ip) - len(keep)


_PROFILE_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")
DEFAULT_PROFILE = "default"


def profiles(conn: sqlite3.Connection) -> list[dict]:
    return [dict(r) for r in conn.execute("SELECT * FROM posture_profiles ORDER BY name != 'default', name")]


def profile(conn: sqlite3.Connection, name: str) -> dict | None:
    row = conn.execute("SELECT * FROM posture_profiles WHERE name = ?", (name,)).fetchone()
    return dict(row) if row else None


def check_profile(name: str, ports: str, intensity, timing, timeout) -> tuple[dict | None, str]:
    """Validate a profile form; returns (profile, "") or (None, error)."""
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
    return {"name": name, "ports": ports, "intensity": intensity, "timing": timing, "timeout": timeout}, ""


def save_profile(conn: sqlite3.Connection, p: dict, note: str, by: str) -> None:
    conn.execute("""INSERT INTO posture_profiles (name, ports, intensity, timing, timeout, note, updated, updated_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(name) DO UPDATE SET ports = excluded.ports,
                    intensity = excluded.intensity, timing = excluded.timing, timeout = excluded.timeout,
                    note = excluded.note, updated = excluded.updated, updated_by = excluded.updated_by""",
                 (p["name"], p["ports"], p["intensity"], p["timing"], p["timeout"], note[:200], db.now(), by))


def delete_profile(conn: sqlite3.Connection, name: str) -> bool:
    """The default profile stays; past scans keep their recorded parameters."""
    if name == DEFAULT_PROFILE:
        return False
    return conn.execute("DELETE FROM posture_profiles WHERE name = ?", (name,)).rowcount > 0


def enqueue(conn: sqlite3.Connection, domain: str, found: list[dict], prof: dict | str, requested_by: str,
            batch: list[int] | None = None) -> int:
    """Queue one posture scan per address with the profile's parameters (prof: name, ports, intensity, timing,
    timeout; a bare port list means the default knobs); an address already queued or running for the domain is
    left alone. Returns how many were queued. batch, when given, gets the row id per address (new or already
    pending): the set the progress dialog follows."""
    if isinstance(prof, str):
        prof = {"name": "", "ports": prof, "intensity": 2, "timing": 3, "timeout": 120}
    n = 0
    for t in found:
        row = conn.execute("""SELECT id FROM posture_scans WHERE domain = ? AND ip = ?
                              AND status IN ('queued', 'running')""", (domain, t["ip"])).fetchone()
        if row:
            if batch is not None:
                batch.append(row["id"])
            continue
        cur = conn.execute("""INSERT INTO posture_scans (domain, ip, hosts, country, ports, status, requested_by,
                              created, profile, intensity, timing, timeout) VALUES (?, ?, ?, ?, ?, 'queued', ?, ?, ?,
                              ?, ?, ?)""",
                           (domain, t["ip"], ",".join(t["hosts"]), t["country"], prof["ports"], requested_by,
                            db.now(), prof["name"], prof["intensity"], prof["timing"], prof["timeout"]))
        if batch is not None:
            batch.append(cur.lastrowid)
        n += 1
    return n


def pending_ids(conn: sqlite3.Connection, domain: str = "") -> list[int]:
    """Ids of the queued and running rows (of one domain, or all)."""
    where, args = ("AND domain = ?", (domain,)) if domain else ("", ())
    return [r[0] for r in conn.execute(f"SELECT id FROM posture_scans WHERE status IN ('queued', 'running') {where} "
                                       "ORDER BY id", args)]


def _worst(services: list[dict]) -> str:
    sevs = {f["severity"] for s in services for f in s.get("findings") or []}
    return next((x for x in SEVERITIES if x in sevs), "none")


def progress(conn: sqlite3.Connection, ids: list[int]) -> dict:
    """Progress of a set of posture_scans rows (one request's batch) for the progress dialog: counts, the addresses
    running now, seconds since the first was queued, and one item per row with its result."""
    rows = [dict(r) for r in conn.execute(
        f"""SELECT id, domain, ip, hosts, status, created, started, finished, services, open_ports, cves, high, error
            FROM posture_scans WHERE id IN ({",".join("?" * len(ids))}) ORDER BY id""", ids)] if ids else []
    count = {s: sum(1 for r in rows if r["status"] == s) for s in ("queued", "running", "done", "failed")}
    finished = count["queued"] + count["running"] == 0
    elapsed = 0
    if rows:
        start = datetime.fromisoformat(min(r["created"] for r in rows))
        end = datetime.fromisoformat(max(r["finished"] or "" for r in rows)) if finished else datetime.now()
        elapsed = max(0, int((end - start).total_seconds()))
    items = [{"id": r["id"], "domain": r["domain"], "ip": r["ip"], "host": (r["hosts"] or "").split(",")[0],
              "status": r["status"], "finished": r["finished"] or "", "open_ports": r["open_ports"], "cves": r["cves"],
              "high": r["high"], "error": r["error"] or "",
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


def run(conn: sqlite3.Connection, row: dict, cve_db: cve.Database, client: httpx.Client | None,
        api_key: str = "") -> None:
    """Run one claimed row. The scope is checked again: it may have changed while the row waited."""
    if not users.posture_ok(users.get_scope(conn), row["ip"], row["country"]):
        _finish(conn, row["id"], "failed", {"error": "outside the posture scope (Settings changed after queueing)"})
        return
    cfg = proxy.get(conn)   # read per scan: a change on the Scan settings page applies to the next one
    try:
        via = proxy.hop(conn, cfg, "posture", row["ip"], row["country"], client)
    except proxy.ProxyError as exc:   # fail closed: never a direct scan instead
        _finish(conn, row["id"], "failed", {"error": f"route: {exc}",
                                            "params": f"via {proxy.describe(cfg, 'posture')}"})
        log.info("posture %s %s: route: %s", row["domain"], row["ip"], exc)
        return
    try:
        with proxy.cve_client(via, client) as lookups:
            res = fingerprint.scan(row["ip"], cve_db=cve_db, client=lookups, api_key=api_key, ports=row["ports"],
                                   display=row["hosts"].split(",")[0] or row["ip"],
                                   intensity=row.get("intensity", 2), timing=row.get("timing", 3),
                                   timeout=row.get("timeout", 120), via=via)
    except Exception as exc:   # one bad host must not stop the queue
        log.exception("posture scan %s failed", row["ip"])
        res = {"error": f"internal error ({type(exc).__name__})"}
    _finish(conn, row["id"], "failed" if res.get("error") else "done", res)
    log.info("posture %s %s: %s", row["domain"], row["ip"], res.get("error") or "done")


def fail_running(conn: sqlite3.Connection) -> int:
    """Rows a crash or restart left running."""
    return conn.execute("UPDATE posture_scans SET status = 'failed', finished = ?, error = 'worker restarted' "
                        "WHERE status = 'running'", (db.now(),)).rowcount


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
        r["sev_n"] = {x: n for x in SEVERITIES if (n := sum(1 for v in r["vulns"] if v["severity"] == x))}
        r["fixable"] = sum(1 for v in r["vulns"] if v["fixes"])
        done = r["status"] == "done"
        r["worst"] = next((x for x in SEVERITIES if x in sevs), "none") if done else ""
        r["stale"] = bool(r.get("finished") and r["finished"] < cutoff)
    table = sorted(vulns.values(), key=lambda v: cve.rank(v["severity"], v["score"]))
    for v in table:
        v["products"] = sorted(v["products"])
    rank = {s: i for i, s in enumerate((*SEVERITIES, "none", ""))}
    rows = sorted(rows, key=lambda r: (rank[r["worst"]], -r["high"], -r["cves"], r["ip"]))
    by_sev = {s: sum(1 for v in table if v["severity"] == s) for s in SEVERITIES}
    risky = sorted((r for r in rows if r["vulns"]),
                   key=lambda r: (*(-r["sev_n"].get(s, 0) for s in SEVERITIES), r["ip"]))[:TOP_HOSTS]
    return {
        "rows": rows, "vulns": table, "by_sev": by_sev,
        "kpi": {"addresses": len(rows), "exposed": sum(1 for r in rows if r["worst"] in ("critical", "high")),
                "cves": len(table), "critical": by_sev["critical"], "high": by_sev["high"],
                "fixable": sum(1 for v in table if v["fixable"]),
                "open_ports": sum(r["open_ports"] for r in rows if r["status"] == "done"),
                "failed": sum(1 for r in rows if r["status"] == "failed"),
                "pending": sum(1 for r in rows if r.get("pending") or r["status"] in ("queued", "running")),
                "stale": sum(1 for r in rows if r["stale"])},
        "charts": {
            # riskiest addresses: distinct CVEs per severity, worst first (click opens the address below)
            "hosts": [{"label": (r.get("hosts") or "").split(",")[0] or r["ip"], "ip": r["ip"],
                       "anchor": anchor(r["ip"]), **{s: r["sev_n"].get(s, 0) for s in SEVERITIES}} for r in risky],
            # per severity: distinct CVEs an update fixes today vs those still without a published fix
            "fix": [{"label": s, "fix": sum(1 for v in table if v["severity"] == s and v["fixable"]),
                     "nofix": sum(1 for v in table if v["severity"] == s and not v["fixable"])}
                    for s in SEVERITIES if by_sev[s]],
            "age": age_buckets(rows),
            "services": [{"label": k, "n": n} for k, n in sorted(services.items(), key=lambda x: -x[1])[:8]]},
    }


TOP_HOSTS = 10
AGE_BUCKETS = ("under 7 days", "7-30 days", f"over {STALE_DAYS} days", "failed", "not finished")


def anchor(ip: str) -> str:
    """Element id of an address's headline in the report."""
    return "pa-" + ip.replace(":", "-").replace(".", "-")


def age_buckets(rows: list[dict], now: datetime | None = None) -> list[dict]:
    """Addresses by the age of their current result: how current the picture is. Empty when nothing to show."""
    now = now or datetime.now()
    n = dict.fromkeys(AGE_BUCKETS, 0)
    for r in rows:
        if r["status"] == "failed":
            n["failed"] += 1
        elif r["status"] != "done" or not r.get("finished"):
            n["not finished"] += 1
        else:
            age = now - datetime.fromisoformat(r["finished"])   # same edge as `stale`
            n[AGE_BUCKETS[2] if age > timedelta(days=STALE_DAYS) else AGE_BUCKETS[0] if age < timedelta(days=7)
              else AGE_BUCKETS[1]] += 1
    return [{"label": k, "n": v} for k, v in n.items()] if rows else []


TREND_DAYS = 90


def trend(conn: sqlite3.Connection, domain: str = "", host: str = "") -> list[dict]:
    """Exposure over time: per day with a finished scan, the distinct critical and high CVEs across the addresses'
    latest successful scans as of that day (the last TREND_DAYS such days). One day says nothing: empty then."""
    where, args = ("AND domain = ?", (domain,)) if domain else ("", ())
    state: dict[tuple[str, str], dict[str, str]] = {}   # (domain, ip) -> {cve: severity}
    days: dict[str, dict] = {}
    for r in conn.execute(f"""SELECT domain, ip, hosts, finished, services FROM posture_scans
                              WHERE status = 'done' AND finished IS NOT NULL {where} ORDER BY finished, id""", args):
        if host and host not in (r["hosts"] or "").split(","):
            continue
        state[(r["domain"], r["ip"])] = {f["cve"]: f["severity"] for s in json.loads(r["services"] or "[]")
                                         for f in s.get("findings") or []}
        cves = {c: sev for found in state.values() for c, sev in found.items()}
        days[r["finished"][:10]] = {"day": r["finished"][:10],
                                    "critical": sum(1 for s in cves.values() if s == "critical"),
                                    "high": sum(1 for s in cves.values() if s == "high")}
    out = list(days.values())[-TREND_DAYS:]
    return out if len(out) > 1 else []


def domains(conn: sqlite3.Connection) -> list[str]:
    """Domains with a finished inventory scan, for the target pick-list."""
    return [r[0] for r in conn.execute(f"SELECT d.name FROM domains d JOIN ({db.LATEST}) s ON s.domain_id = d.id "
                                       "ORDER BY d.name")]


def hosts(conn: sqlite3.Connection, domain: str) -> list[str]:
    """Host names with an address in the domain's latest inventory scan, for the host pick-list."""
    return [r[0] for r in conn.execute(f"""SELECT DISTINCT r.host FROM records r JOIN ({db.LATEST}) s
        ON s.id = r.scan_id JOIN domains d ON d.id = s.domain_id WHERE d.name = ? AND r.ip != '' ORDER BY r.host""",
        (domain,))]
