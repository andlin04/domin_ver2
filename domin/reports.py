"""Posture reports: an executive and technical report on picked host names of one domain, as Markdown or PDF.

build() gathers the facts once (current posture results of the picked names' addresses); markdown() and pdf()
only lay them out, so both files say the same thing. Recommendations are rules on those facts, never free text."""

from __future__ import annotations

import re
import sqlite3
from datetime import datetime

from fpdf import FPDF
from fpdf.fonts import FontFace

from . import cve, exploits, posture

# services that should rarely face the internet: named in the attack-surface recommendation when open
RISKY_PORTS = {21: "FTP", 23: "Telnet", 69: "TFTP", 111: "RPC", 135: "MS-RPC", 139: "NetBIOS", 445: "SMB",
               1433: "MS SQL", 1521: "Oracle DB", 2049: "NFS", 2375: "Docker API", 3306: "MySQL", 3389: "RDP",
               5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached",
               27017: "MongoDB"}
RATING = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "unknown": "Unrated",
          "none": "No known vulnerabilities", "": "Not assessed"}
TOP_RISKS = 10
MAX_HOSTS = 3000
MAX_DOMAINS = 1000


def _only(r: dict, want: set[str], cves: set[str] | None) -> dict:
    """A posture row narrowed to the report's picks: host names to the ticked ones (an address shared with names
    not ticked does not list them) and, with cves, findings to those CVEs (the page's filters)."""
    names = [n for n in (r.get("hosts") or "").split(",") if n in want]
    r = {**r, "hosts": ",".join(names) if names else r.get("hosts")}
    if cves is not None:
        r["services"] = [{**s, "findings": [f for f in s.get("findings") or [] if f["cve"] in cves]}
                         for s in r["services"]]
        found = {f["cve"]: f["severity"] for s in r["services"] for f in s["findings"]}
        r["cves"], r["high"] = len(found), sum(1 for v in found.values() if v in ("critical", "high"))
    return r


def build(conn: sqlite3.Connection, picks: dict[str, list[str] | None], by: str = "",
          cves: set[str] | None = None) -> dict:
    """The report's facts for picked domains: {domain: picked host names, or None for all of them}. Unknown names
    are ignored. cves: only these CVEs (the CVEs the page's filters leave), None = all. Several domains add a
    per-domain table. Every host name gets a section (sections()), worst first like the host table."""
    names: list[dict] = []
    raw: list[dict] = []
    for dom, want in list(picks.items())[:MAX_DOMAINS]:
        found = [h for h in posture.host_list(conn, dom) if want is None or h["host"] in set(want)]
        ips = {ip for h in found for ip in h["ips"]}
        keep = {h["host"] for h in found}
        raw += [_only(r, keep, cves) for r in posture.current(conn, dom) if r["ip"] in ips]
        names += [{**h, "domain": dom} for h in found]
    names = names[:MAX_HOSTS]
    rep = posture.report(raw)
    rows = rep["rows"]
    # exploit facts from the local table only (exploits.annotate_report); shown only when the feature is on and
    # at least one CVE has some, so a report without them reads as before
    xp = exploits.annotate_report(conn, rep) and any(v["xp"]["tier"] != "none" or "epss" in v["xp"]
                                                     for v in rep["vulns"])
    hosts = [h for dom in picks for h in posture.with_results([n for n in names if n["domain"] == dom],
                                                                [r for r in rows if r["domain"] == dom])]
    hosts.sort(key=lambda h: (h["rank"], *(-h["sev_n"].get(s, 0) for s in posture.SEVERITIES), h["host"]))
    doms = sorted({h["domain"] for h in names})
    many = len(doms) > 1
    done = [r for r in rows if r["status"] == "done"]
    worst = next((s for s in (*posture.SEVERITIES, "none") if any(r["worst"] == s for r in done)), "")
    finished = sorted(r["finished"] for r in done if r.get("finished"))
    domain = f"{len(doms)} domains" if many else (doms[0] if doms else "")
    # one machine (one row of the host table: names sharing the same addresses, posture.by_address) is named after
    # its first host name; its other names are aliases
    machines = {tuple(sorted(h["ips"])) for h in hosts}
    one = min(h["host"] for h in hosts) if hosts and not many and len(machines) == 1 else ""
    alias = f" (+ {len(hosts) - 1} alias{'es' if len(hosts) > 2 else ''})" if len(hosts) > 1 else ""
    return {
        "domain": domain, "domains": doms,
        # what the report is on, for its title and file name: the host name when it covers one machine
        "subject": one or domain,
        "title": one + alias if one else (f"{domain} ({len(hosts)} hosts)" if len(hosts) > 1 and not many
                                          else domain),
        "domain_rows": posture.domain_summary(rows) if many else [],
        "sections": sections(hosts, rows, many),
        "charts": {**rep["charts"], "trend": posture.trend(conn, only={(r["domain"], r["ip"]) for r in rows},
                                                           cves=cves)},
        "by": by, "created": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "hosts": hosts, "rows": rows, "vulns": rep["vulns"], "kpi": rep["kpi"], "by_sev": rep["by_sev"],
        "rating": RATING[worst], "worst": worst,
        "period": (finished[0][:10], finished[-1][:10]) if finished else ("", ""),
        "profiles": sorted({r.get("profile") or "default" for r in done}),
        "never": [h["host"] for h in hosts if not h["results"]],
        "top": [v for v in rep["vulns"] if v["severity"] in ("critical", "high")][:TOP_RISKS],
        "actions": actions(rep["vulns"], rows, hosts),
        "source": cve.SOURCE,
        "xp": xp, "xp_counts": rep.get("xp_counts", {}) if xp else {},
        "filtered": cves is not None,
        "xp_updated": exploits.last_updated(conn) if xp else "",
    }


def _names(v: dict) -> list[str]:
    return sorted({name or ip for ip, name in v["addresses"]})


def _more(items: list, n: int) -> str:
    return ", ".join(items[:n]) + (f" and {len(items) - n} more" if len(items) > n else "")


def _cut(s: str, n: int) -> str:
    """At most n characters, cut at a word."""
    s = " ".join((s or "").split())
    return s if len(s) <= n else s[:n].rsplit(" ", 1)[0] + " ..."


def actions(vulns: list[dict], rows: list[dict], hosts: list[dict], one: bool = False) -> list[dict]:
    """Prioritised recommendations: patch (critical/high with a published fix, per product), mitigate (critical/high
    without one), reduce exposure (services that rarely belong on the internet), then medium/low patching and
    coverage gaps. Each: priority (1 = first), title, detail. one: for a single host's section (no host lists)."""
    out: list[dict] = []
    serious = [v for v in vulns if v["severity"] in ("critical", "high")]
    patch: dict[str, dict] = {}
    for v in serious:
        if v["fixable"]:
            for p in v["products"]:
                g = patch.setdefault(p, {"cves": [], "fixes": set(), "hosts": set()})
                g["cves"].append(v["cve"])
                g["fixes"].update(v["fixes"])
                g["hosts"].update(_names(v))
    for p, g in sorted(patch.items(), key=lambda x: -len(x[1]["cves"])):
        plain = [f for f in g["fixes"] if not f.startswith("after")] or sorted(g["fixes"])
        target = max(plain, key=lambda f: tuple(int(x) for x in re.findall(r"\d+", f)))
        goal = f"a version {target}" if target.startswith("after") else f"{target} or later"
        out.append({"priority": 1, "title": f"Update {p} to {goal}",
                    "detail": f"Fixes {len(g['cves'])} critical/high CVE(s): {_more(g['cves'], 5)}."
                              f" {target} is the newest fixed version they name."
                              + ("" if one else f" Hosts: {_more(sorted(g['hosts']), 8)}.")})
    nofix = [v for v in serious if not v["fixable"]]
    if nofix:
        prods = sorted({p for v in nofix for p in v["products"]})
        out.append({"priority": 1, "title": "Mitigate vulnerabilities without a published fix",
                    "detail": f"{len(nofix)} critical/high CVE(s) in {_more(prods, 6)} have no fixed version yet:"
                              " restrict access (firewall or allow-list), disable the affected feature, and follow"
                              " the vendor advisory."})
    risky: dict[str, set] = {}
    for r in rows:
        for s in r["services"]:
            if s.get("port") in RISKY_PORTS:
                key = f"{RISKY_PORTS[s['port']]} ({s['port']}/{s.get('proto') or 'tcp'})"
                risky.setdefault(key, set()).add((r.get("hosts") or "").split(",")[0] or r["ip"])
    if risky:
        out.append({"priority": 2, "title": "Reduce the attack surface",
                    "detail": "Services that rarely belong on the internet are reachable: "
                              + "; ".join(k if one else f"{k} on {_more(sorted(h), 4)}"
                                          for k, h in sorted(risky.items()))
                              + ". Close them or limit them to known source addresses or a VPN."})
    rest = [v for v in vulns if v["severity"] not in ("critical", "high") and v["fixable"]]
    if rest:
        out.append({"priority": 3, "title": "Plan routine patching",
                    "detail": f"{len(rest)} medium/low CVE(s) have a published fix; include them in the next"
                              " maintenance window."})
    gaps = []
    if n := sum(1 for h in hosts if not h["results"]):
        gaps.append(f"{n} host name(s) never scanned")
    if n := sum(1 for r in rows if r.get("blocked")):
        gaps.append(f"{n} address(es) answered on no port (filtered or blocked)")
    if n := sum(1 for r in rows if r["status"] == "failed"):
        gaps.append(f"{n} scan(s) failed")
    if n := sum(1 for r in rows if r.get("stale")):
        gaps.append(f"{n} result(s) older than {posture.STALE_DAYS} days")
    if gaps:
        out.append({"priority": 3, "title": "Close coverage gaps",
                    "detail": "; ".join(gaps) + ". Rescan these before relying on this report for them."})
    return out


def _slug(s: str) -> str:
    return "host-" + "-".join(re.findall(r"[a-z0-9]+", s.lower()))


def _sev_counts(sev_n: dict) -> str:
    return ", ".join(f"{sev_n[s]} {s}" for s in posture.SEVERITIES if sev_n.get(s)) or "none"


def sections(hosts: list[dict], rows: list[dict], many: bool) -> list[dict]:
    """One section per host name (hosts: with_results entries, in report order) with everything about it: facts,
    status notes, services and CVEs of all its addresses (`ip` set on each, shown when it has several), and the
    host's own actions (actions() on its findings). `anchor` links the host table to the section."""
    by_ip = {(r["domain"], r["ip"]): r for r in rows}
    out, seen = [], set()
    for h in hosts:
        res = [by_ip[(h["domain"], ip)] for ip in h["ips"] if (h["domain"], ip) in by_ip]
        notes = []
        if not res:
            notes.append("Never scanned" + (": a scan is queued." if h.get("pending") else "."))
        elif missing := [ip for ip in h["ips"] if (h["domain"], ip) not in by_ip]:
            notes.append(f"No scan result yet for {_more(missing, 6)}.")
        if h.get("skip"):
            notes.append(f"Left out of posture scans: {h['skip']}.")
        for r in res:
            pre = f"{r['ip']}: " if len(h["ips"]) > 1 else ""
            if r["status"] == "failed":
                notes.append(f"{pre}the last scan failed" + (f" ({r['error']})." if r.get("error") else "."))
            elif r.get("error"):
                notes.append(f"{pre}error: {r['error']}.")
            if r.get("blocked"):
                notes.append(f"{pre}{r.get('note') or 'Potentially blocked: no scanned port answered.'}")
            elif r.get("note"):
                notes.append(f"{pre}{r['note']}")
            if r.get("stale"):
                notes.append(f"{pre}the result is older than {posture.STALE_DAYS} days.")
            if r.get("status") in ("queued", "running") or r.get("pending"):
                notes.append(f"{pre}a newer scan is queued or running.")
        notes = [n[:1].upper() + n[1:] for n in notes]
        services = [{**s, "ip": r["ip"]} for r in res for s in r["services"]]
        merged: dict[str, dict] = {}
        for r in res:
            for v in r.get("vulns") or []:
                e = merged.setdefault(v["cve"], {**v, "where": [], "fixes": list(v["fixes"]), "ips": []})
                e["where"] += [(*w, r["ip"]) for w in v["where"]]
                e["fixes"] += [f for f in v["fixes"] if f not in e["fixes"]]
                e["ips"].append(r["ip"])
        vulns = sorted(merged.values(), key=lambda v: cve.rank(v["severity"], v["score"]))
        for v in vulns:
            v["products"] = sorted({w[0] for w in v["where"]})
            v["fixable"] = bool(v["fixes"])
            v["addresses"] = [(ip, h["host"]) for ip in v["ips"]]
        a = _slug(f"{h['host']} {h['domain']}" if many else h["host"])
        while a in seen:
            a += "-x"
        seen.add(a)
        out.append({**h, "anchor": a, "res": res, "notes": notes, "services": services, "vulns": vulns,
                    "multi": len({x["ip"] for x in services}) > 1,
                    "profiles": sorted({r.get("profile") or "default" for r in res if r["status"] == "done"}),
                    "todo": actions(vulns, res, [h], one=True)})
    return out


def facts(s: dict, many: bool) -> list[tuple[str, str]]:
    """A host section's facts (label, value), shared by both formats."""
    out = [("Rating", RATING[s["worst"]]), ("Addresses", ", ".join(s["ips"])), ("Open ports", str(s["open_ports"])),
           ("CVEs", f"{s['cves']} ({_sev_counts(s['sev_n'])})" if s["cves"] else "none"),
           ("Fixable", f"{s['fixable']}/{s['cves']}"), ("Last scan", s["last"] or "never"),
           ("Scan profile", ", ".join(s["profiles"]) or "none")]
    if many:
        out.insert(1, ("Domain", s["domain"]))
    if s.get("tags"):
        out.append(("Tags", ", ".join(s["tags"])))
    return out


def _where(s: dict, v: dict) -> str:
    """Product and port(s) of a CVE on a host, with the address when the host has several."""
    return "; ".join(dict.fromkeys(f"{prod} ({port}/{proto}{' on ' + ip if s['multi'] else ''})"
                                   for prod, port, proto, ip in v["where"]))


def _svc(s: dict, x: dict) -> list[str]:
    """A service row: [address when several,] port/proto, service, product + version, CVE count."""
    return [*([x["ip"]] if s["multi"] else []), f"{x['port']}/{x.get('proto') or 'tcp'}", x.get("service") or "",
            " ".join(y for y in (x.get("product"), x.get("version")) if y), str(len(x.get("findings") or []))]


def clean_line(s: dict) -> str:
    """The sentence for a host without CVEs."""
    if not any(r["status"] == "done" for r in s["res"]):
        return "No finished scan, so nothing is known about this host yet."
    ports = "; ".join(f"{x['port']}/{x.get('proto') or 'tcp'} {x.get('service') or ''}".strip()
                      + (f" ({' '.join(y for y in (x.get('product'), x.get('version')) if y)})"
                         if x.get("product") else "") + (f" on {x['ip']}" if s["multi"] else "")
                      for x in s["services"])
    return f"No known vulnerabilities; {s['open_ports']} open port(s)" + (f": {ports}." if ports else ".")


def summary_lines(m: dict) -> list[str]:
    """The executive summary in a few plain sentences (shared by both formats)."""
    k = m["kpi"]
    lines = [f"Overall risk: {m['rating']}. {len(m['hosts'])} host name(s) of {m['domain']} on {k['addresses']}"
             f" address(es) were assessed; {k['open_ports']} open port(s) and {k['cves']} distinct known"
             " vulnerabilities (CVEs) were found."]
    if k["cves"]:
        lines.append(f"{k['critical']} critical and {k['high']} high CVE(s) affect {k['exposed']} address(es)."
                     f" {k['fixable']} of {k['cves']} CVE(s) are fixed by a published update.")
    else:
        lines.append("No known vulnerabilities were matched to the detected service versions.")
    if m.get("xp"):
        n = m["xp_counts"]
        lines.append(f"Exploit data: {n.get('kev', 0)} CVE(s) known exploited in the wild (CISA KEV),"
                     f" {n.get('exploit', 0)} more with public exploit code and {n.get('poc', 0)} more with only"
                     " proof-of-concept repositories.")
    first = [a["title"] for a in m["actions"] if a["priority"] == 1][:3]
    if first:
        lines.append("First actions: " + "; ".join(first) + ".")
    return lines


def xp_marks(x: dict) -> str:
    """A CVE's exploit markers as text (finding.xp from exploits.annotate): KEV (date, ransomware), exploit, PoC,
    EPSS; '' when it has none."""
    out = []
    if x.get("kev"):
        out.append(f"KEV (added {x['kev']['added']}" + (", ransomware)" if x["kev"]["ransomware"] else ")"))
    if x.get("edb") or x.get("msf") or x.get("nvd"):
        out.append("exploit")
    if x.get("poc"):
        out.append("PoC")
    if "epss" in x:
        out.append(f"EPSS {x['epss'] * 100:.1f}%")
    return " · ".join(out)


POC_NOTE = "PoC, unverified third-party code"


def xp_refs(x: dict) -> list[tuple[str, str]]:
    """A CVE's exploit reference links (label, url): CISA KEV, Exploit-DB, Metasploit, NVD exploit references, PoC
    repositories. Links only: nothing is fetched, no code is included."""
    out = []
    if x.get("kev"):
        out.append(("CISA KEV", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                                f"?search_api_fulltext={x['cve_id']}"))
    out += [(f"Exploit-DB {e['id']}", e["url"]) for e in x.get("edb") or []]
    out += [(f"Metasploit {m['module']}", m["url"]) for m in x.get("msf") or []]
    out += [("NVD exploit reference", u) for u in x.get("nvd") or []]
    out += [(f"{p['name']} ({POC_NOTE})", p["url"]) for p in x.get("poc") or []]
    return out


def _xp(m: dict, v: dict) -> dict:
    """The finding's exploit facts when the report shows them, else {}."""
    return (v.get("xp") or {}) if m.get("xp") else {}


NO_TODO = "No update or setting change applies; watch for vendor fixes."


def _score(v: dict) -> str:
    return f"{v['score']:.1f}" if v.get("score") else ""


def _sev(v: dict) -> str:
    return v["severity"] + (f" {v['score']:.1f}" if v.get("score") else "")


def _period(m: dict) -> str:
    a, b = m["period"]
    return "no finished scans" if not a else a if a == b else f"{a} to {b}"


def _status(r: dict) -> str:
    when = (r.get("finished") or "")[:16].replace("T", " ") or "not finished"
    prof = r.get("profile") or "default"
    return f"Rating {RATING[r['worst']]} · status {r['status']} · finished {when} · profile {prof}"


def _byline(m: dict) -> str:
    by = f" by {m['by']}" if m["by"] else ""
    return f"Created {m['created']}{by} · scans {_period(m)} · {len(m['hosts'])} host name(s)"


def _cell(s) -> str:
    """A Markdown table cell: no pipes or line breaks."""
    return " ".join(str(s).replace("|", "/").split())


SCOPE = ("Scope: the {n} host name(s) picked in the posture view of {domain}, with their addresses from the latest"
         " inventory scan.")
SCOPE_MANY = ("Scope: every host name of the {n} domains picked in the posture view ({names}), with their addresses"
              " from each domain's latest inventory scan.")


def heads(m: dict) -> dict[str, str]:
    """Section titles, numbered: the Domains section only in a report on several domains."""
    names = ["Executive summary", "Recommendations", "Statistics", "Top risks",
             *(["Domains"] if m["domain_rows"] else []),
             "Hosts", "Host findings", "Scope and method"]
    return {n: f"{i}. {n}" for i, n in enumerate(names, 1)}


def _dom_cells(d: dict) -> list:
    """One row of the Domains table: domain, worst, CVEs (critical/high), fixable, addresses with high+, open ports."""
    return [d["domain"], (SHORT.get(d["worst"], d["worst"] or "Not assessed"), d["worst"]),
            f"{d['cves']} ({d['sev_n'].get('critical', 0)}/{d['sev_n'].get('high', 0)})",
            f"{d['fixable']}/{d['cves']}", f"{d['exposed']}/{d['addresses']}", d["open_ports"]]
METHOD = ("Method: network service and version detection (scan profiles: {profiles}), matched against known"
          " vulnerabilities ({source}). Scans: {period}.")
XP_METHOD = ("Exploit data (information only, last updated {updated}): KEV = known exploited in the wild (CISA KEV"
             " catalog), exploit = public exploit code listed by Exploit-DB, Metasploit or an NVD reference tagged"
             " Exploit, PoC = proof-of-concept repositories listed by PoC-in-GitHub (unverified third-party code),"
             " EPSS = FIRST's probability of exploitation in the next 30 days. The report holds links only, no"
             " exploit code.")
LIMITS = ("Limits: matches are by product version; vendors that backport fixes can show false positives, and services"
          " that hide their version can hide vulnerabilities. Addresses that answered on no port are not assessed.")


def _method(m: dict) -> list[str]:
    scope = (SCOPE_MANY.format(n=len(m["domains"]), names=_more(m["domains"], 20)) if m["domain_rows"]
             else SCOPE.format(n=len(m["hosts"]), domain=m["domain"]))
    xp = [XP_METHOD.format(updated=m["xp_updated"] or "unknown")] if m.get("xp") else []
    if m.get("filtered"):
        scope += " Filtered: only the CVEs the posture view's filters showed when the report was made."
    return [scope,
            METHOD.format(profiles=", ".join(m["profiles"]) or "none", source=m["source"], period=_period(m)),
            *xp, LIMITS] +([f"Never scanned: {', '.join(m['never'])}."] if m["never"] else [])


def _md_host(m: dict, s: dict) -> list[str]:
    """One host's section in Markdown."""
    many = bool(m["domain_rows"])
    md = [f'<a id="{s["anchor"]}"></a>', "", f"### {s['host']}" + (f" ({s['domain']})" if many else ""), "",
          " · ".join(f"**{k}:** {_cell(v)}" for k, v in facts(s, many)), ""]
    md += [f"> {_cell(n)}" for n in s["notes"]] + ([""] if s["notes"] else [])
    if not s["vulns"]:
        return md + [clean_line(s), ""]
    if s["services"]:
        addr = ("Address | ", "---|") if s["multi"] else ("", "")
        md += ["**Services**", "", f"| {addr[0]}Port | Service | Product / version | CVEs |",
               f"|{addr[1]}---|---|---|---:|"]
        md += ["| " + " | ".join(_cell(c) for c in _svc(s, x)) + " |" for x in s["services"]]
        md.append("")
    xh, xl = (" Exploit |", "---|") if m.get("xp") else ("", "")
    md += ["**Vulnerabilities**", "", f"| CVE | Severity | Score |{xh} Fixed in | Product / port |",
           f"|---|---|---:|{xl}---|---|"]
    md += [f"| {v['cve']} | {v['severity']} | {_score(v)} |"
           + (f" {_cell(xp_marks(v.get('xp') or {}))} |" if m.get("xp") else "")
           + f" {_cell(', '.join(v['fixes']) or 'no fix yet')} | {_cell(_where(s, v))} |" for v in s["vulns"]]
    md += ["", "**References**", ""]
    for v in s["vulns"]:
        refs = [*v["links"], *xp_refs(_xp(m, v))]
        md.append(f"- **{v['cve']}**: " + (f"{_cell(_cut(v.get('summary'), 300))} · " if v.get("summary") else "")
                  + " · ".join(f"[{_cell(label)}]({url})" for label, url in refs))
    md += ["", "**What to do on this host**", ""]
    md += [f"{i}. **P{a['priority']} · {a['title']}.** {a['detail']}" for i, a in enumerate(s["todo"], 1)]
    return md + ([] if s["todo"] else [NO_TODO]) + [""]


CHART_TITLES = {"trend": "CVEs over time", "fix": "Fix available?", "surface": "Attack surface over time",
                "services": "Exposed services"}
NO_TREND = "Trends need finished scans on two or more days."


def _md_stats(m: dict) -> list[str]:
    """The posture charts as tables (Markdown cannot hold the PDF's drawings)."""
    ch = m["charts"]
    md = [f"### {CHART_TITLES['trend']} and {CHART_TITLES['surface'].lower()}", "",
          "Distinct CVEs per severity, open ports and addresses scanned on each address's latest scan as of the day.",
          ""]
    if ch["trend"]:
        md += ["| Day | Critical | High | Medium | Low | Open ports | Addresses |",
               "|---|---:|---:|---:|---:|---:|---:|"]
        md += [f"| {t['day']} | {t['critical']} | {t['high']} | {t['medium']} | {t['low']} | {t['ports']}"
               f" | {t['addresses']} |" for t in ch["trend"]]
    else:
        md.append(NO_TREND)
    md += ["", f"### {CHART_TITLES['fix']}", ""]
    if ch["fix"]:
        md += ["| Severity | Fix published | No fix yet |", "|---|---:|---:|"]
        md += [f"| {f['label']} | {f['fix']} | {f['nofix']} |" for f in ch["fix"]]
    else:
        md.append("No CVEs.")
    md += ["", f"### {CHART_TITLES['services']}", ""]
    if ch["services"]:
        md += ["| Service | Open ports | With CVEs |", "|---|---:|---:|"]
        md += [f"| {_cell(x['label'])} | {x['n']} | {x['vuln']} |" for x in ch["services"]]
    else:
        md.append("No open ports.")
    return md + [""]


def markdown(m: dict) -> str:
    """The report as Markdown."""
    k, h_ = m["kpi"], heads(m)
    md = [f"# Security posture report: {m['title']}", "", _byline(m), "",
          f"## {h_['Executive summary']}", "", *summary_lines(m), "",
          "| Overall risk | Critical | High | Medium | Low | Fixable | Open ports | Addresses |",
          "|---|---:|---:|---:|---:|---:|---:|---:|",
          f"| **{m['rating']}** | {k['critical']} | {k['high']} | {m['by_sev']['medium']} | {m['by_sev']['low']}"
          f" | {k['fixable']}/{k['cves']} | {k['open_ports']} | {k['addresses']} |", "",
          f"## {h_['Recommendations']}", ""]
    if m["actions"]:
        md += [f"{i}. **P{a['priority']} · {a['title']}.** {a['detail']}" for i, a in enumerate(m["actions"], 1)]
    else:
        md.append("No action needed on the current results.")
    md += ["", f"## {h_['Statistics']}", "", *_md_stats(m), f"## {h_['Top risks']}", ""]
    if m["top"]:
        xh, xl = (" Exploit |", "---|") if m.get("xp") else ("", "")
        md += [f"| CVE | Severity |{xh} Product | Fixed in | Hosts |", f"|---|---|{xl}---|---|---|"]
        md += [f"| [{v['cve']}]({posture.links(v)[0][1]}) | {_sev(v)} |"
               + (f" {_cell(xp_marks(v['xp']))} |" if m.get("xp") else "")
               + f" {_cell(', '.join(v['products']))} |"
               f" {_cell(', '.join(v['fixes']) or 'no fix yet')} | {_cell(', '.join(_names(v)))} |" for v in m["top"]]
    else:
        md.append("No critical or high vulnerabilities.")
    if m["domain_rows"]:
        md += ["", f"## {h_['Domains']}", "",
               "| Domain | Rating | CVEs (critical/high) | Fixable | Addresses with high+ | Open ports |",
               "|---|---|---:|---:|---:|---:|"]
        md += ["| " + " | ".join(str(x[0] if isinstance(x, tuple) else x) for x in _dom_cells(d)) + " |"
               for d in m["domain_rows"]]
    md += ["", f"## {h_['Hosts']}", "",
           "| Host name | Addresses | Rating | CVEs (critical/high) | Fixable | Open ports | Last scan |",
           "|---|---|---|---:|---:|---:|---|"]
    md += [f"| [{h['host']}](#{h['anchor']}) | {', '.join(h['ips'])} | {RATING[h['worst']]} | {h['cves']}"
           f" ({h['sev_n'].get('critical', 0)}/{h['sev_n'].get('high', 0)}) | {h['fixable']} | {h['open_ports']}"
           f" | {h['last'] or 'never'} |" for h in m["sections"]]
    md += ["", f"## {h_['Host findings']}", ""]
    for x in m["sections"]:
        md += _md_host(m, x)
    md += [f"## {h_['Scope and method']}", "", *(f"- {x}" for x in _method(m)), ""]
    return "\n".join(md)


# ------------------------------------------------------------------------------------------------------------- PDF
INK, MUTED, LINE, ACCENT, ZEBRA = (33, 37, 41), (108, 117, 125), (222, 226, 230), (31, 78, 121), (244, 246, 248)
SHORT = {**RATING, "none": "None found"}


def _ips(ips: list[str], n: int = 3) -> str:
    return ", ".join(ips[:n]) + (f" +{len(ips) - n} more" if len(ips) > n else "")
SEV_RGB = {"critical": (176, 0, 32), "high": (214, 92, 0), "medium": (191, 144, 0), "low": (46, 125, 50),
           "unknown": (108, 117, 125), "none": (46, 125, 50), "": (108, 117, 125)}
DASHES = str.maketrans({"–": "-", "—": "-", "‘": "'", "’": "'", "“": '"', "”": '"',
                        "…": "...", " ": " "})


def _t(s) -> str:
    """Text for the core fonts (Latin-1): typographic punctuation simplified, anything else replaced."""
    return str(s if s is not None else "").translate(DASHES).encode("latin-1", "replace").decode("latin-1")


class _Doc(FPDF):
    def __init__(self, m: dict):
        super().__init__(format="A4")
        self.m = m
        self.set_margins(16, 16, 16)
        self.set_auto_page_break(True, 18)
        self.set_title(_t(f"Security posture report: {m['title']}"))
        self.page_mode = "USE_OUTLINES"   # the viewer opens with the bookmarks (sections, then one per host)
        self.set_creator("domin")
        self.alias_nb_pages("{pages}")   # wide enough for a four-digit page count

    def header(self):
        self.fresh = self.t_margin   # where the page's content starts (a host section here needs no page break)
        if self.page_no() == 1:
            return
        self.set_font("helvetica", "", 8)
        self.set_text_color(*MUTED)
        self.cell(0, 6, _t(f"Security posture report · {self.m['title']} · {self.m['created']}"))
        self.ln(8)
        self.fresh = self.get_y()

    def footer(self):
        self.set_y(-12)
        self.set_font("helvetica", "", 8)
        self.set_text_color(*MUTED)
        self.cell(0, 6, f"Confidential · page {self.page_no()}/{{pages}}", align="R")

    def h1(self, text: str):
        if self.get_y() > self.page_break_trigger - 35:   # never a heading alone at the foot of a page
            self.add_page()
        self.ln(3)
        self.start_section(_t(text))
        self.set_font("helvetica", "B", 13)
        self.set_text_color(*ACCENT)
        self.cell(0, 8, _t(text), new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*ACCENT)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(3)

    def para(self, text: str, size: float = 10, style: str = ""):
        self.set_font("helvetica", style, size)
        self.set_text_color(*INK)
        self.multi_cell(0, size * 0.5, _t(text), new_x="LMARGIN", new_y="NEXT")
        self.ln(1.5)

    def grid(self, head: list[str], rows: list[list], widths: tuple, sev_col: int | None = None, size: float = 8.5,
             links: int | None = None, jumps: list[int] | None = None):
        """A table; a (label, severity) value in sev_col is printed bold in the severity's colour; the URL in column
        links is clickable; jumps: per row, an internal link for the first column."""
        self.set_font("helvetica", "", size)
        self.set_text_color(*INK)
        self.set_draw_color(*LINE)
        head_style = FontFace(emphasis="BOLD", color=(255, 255, 255), fill_color=ACCENT)
        with self.table(col_widths=widths, headings_style=head_style, line_height=size * 0.55, text_align="LEFT",
                        borders_layout="HORIZONTAL_LINES", padding=1.2, cell_fill_color=ZEBRA,
                        cell_fill_mode="ROWS") as t:
            t.row([_t(x) for x in head])
            for n, r in enumerate(rows):
                row = t.row()
                for i, val in enumerate(r):
                    if i == 0 and jumps:
                        row.cell(_t(val), link=jumps[n], style=FontFace(color=ACCENT))
                    elif i == sev_col and isinstance(val, tuple):
                        row.cell(_t(val[0]), style=FontFace(emphasis="BOLD", color=SEV_RGB.get(val[1], INK)))
                    elif i == links:
                        row.cell(_t(val), link=str(val), style=FontFace(color=ACCENT))
                    else:
                        row.cell(_t(val))
        self.ln(3)


CHART_W_GAP, CHART_H = 6, 64
TREND_SERIES = [("critical", "Critical"), ("high", "High"), ("medium", "Medium"), ("low", "Low")]


def _tint(rgb: tuple, k: float = 0.55) -> tuple:
    return tuple(int(c + (255 - c) * k) for c in rgb)


def _plot_frame(d: _Doc, x: float, y: float, w: float, h: float, title: str,
                legend: list[tuple[str, tuple, bool]], top: float, left: float = 9) -> tuple:
    """A chart's title, legend (label, colour, dashed) and y grid (0, half, top); returns the plot area."""
    d.set_xy(x, y)
    d.set_font("helvetica", "B", 9)
    d.set_text_color(*ACCENT)
    d.cell(w, 5, _t(title))
    lx = x
    d.set_font("helvetica", "", 6.5)
    for label, rgb, dashed in legend:
        d.set_draw_color(*rgb)
        d.set_line_width(0.6)
        if dashed:
            d.set_dash_pattern(dash=1, gap=0.8)
        d.line(lx, y + 8, lx + 4, y + 8)
        d.set_dash_pattern()
        d.set_xy(lx + 4.5, y + 6.2)
        d.set_text_color(*MUTED)
        d.cell(d.get_string_width(label) + 1, 3.6, label)
        lx += d.get_string_width(label) + 8
    px, py, pw, ph = x + left, y + 12, w - left - 2, h - 19
    d.set_line_width(0.15)
    d.set_draw_color(*LINE)
    d.set_font("helvetica", "", 6)
    for f in (0, 0.5, 1):
        gy = py + ph - f * ph
        d.line(px, gy, px + pw, gy)
        if top:
            d.set_xy(px - left, gy - 1.6)
            d.cell(left - 1, 3.2, f"{top * f:g}", align="R")
    return px, py, pw, ph


def _chart_lines(d: _Doc, x: float, y: float, w: float, title: str, trend: list[dict],
                 series: list[tuple[str, str, tuple, bool]]):
    """A line chart over the trend's days: series (key, label, colour, dashed), one scale."""
    top = max([t[k] for t in trend for k, _, _, _ in series] + [1])
    px, py, pw, ph = _plot_frame(d, x, y, w, CHART_H, title, [(lb, c, ds) for _, lb, c, ds in series], top)
    n = len(trend)
    for key, _, rgb, dashed in series:
        pts = [(px + (i * pw / (n - 1) if n > 1 else pw / 2), py + ph - t[key] / top * ph) for i, t in enumerate(trend)]
        d.set_draw_color(*rgb)
        d.set_line_width(0.5)
        if dashed:
            d.set_dash_pattern(dash=1, gap=0.8)
        d.polyline(pts)
        d.set_dash_pattern()
    d.set_line_width(0.2)
    d.set_font("helvetica", "", 6)
    d.set_text_color(*MUTED)
    for i in sorted({0, n // 2, n - 1}):
        cx = px + (i * pw / (n - 1) if n > 1 else pw / 2)
        d.set_xy(cx - 9, py + ph + 1)
        d.cell(18, 3.2, trend[i]["day"], align="C")


def _chart_fix(d: _Doc, x: float, y: float, w: float, fix: list[dict]):
    """Stacked bars per severity: CVEs with a published fix (solid) and without (light)."""
    top = max([f["fix"] + f["nofix"] for f in fix] + [1])
    px, py, pw, ph = _plot_frame(d, x, y, w, CHART_H, CHART_TITLES["fix"],
                                 [("fix published", INK, False), ("no fix yet", _tint(INK), False)], top)
    slot = pw / max(len(fix), 1)
    bw = min(slot * 0.55, 14)
    d.set_font("helvetica", "", 6.5)
    for i, f in enumerate(fix):
        rgb = SEV_RGB.get(f["label"], MUTED)
        bx = px + i * slot + (slot - bw) / 2
        hf, hn = f["fix"] / top * ph, f["nofix"] / top * ph
        d.set_fill_color(*rgb)
        if hf:
            d.rect(bx, py + ph - hf, bw, hf, style="F")
        d.set_fill_color(*_tint(rgb))
        if hn:
            d.rect(bx, py + ph - hf - hn, bw, hn, style="F")
        d.set_text_color(*INK)
        d.set_xy(bx - 3, py + ph - hf - hn - 3.6)
        d.cell(bw + 6, 3.2, f"{f['fix']}/{f['nofix']}", align="C")
        d.set_text_color(*MUTED)
        d.set_xy(px + i * slot, py + ph + 1)
        d.cell(slot, 3.2, f["label"], align="C")
    d.set_fill_color(255, 255, 255)


def _chart_services(d: _Doc, x: float, y: float, w: float, services: list[dict]):
    """Horizontal bars: open ports per service, the part with CVEs in the high colour."""
    top = max([s["n"] for s in services] + [1])
    px, py, pw, ph = _plot_frame(d, x, y, w, CHART_H, CHART_TITLES["services"],
                                 [("open ports", _tint(ACCENT, 0.35), False),
                                  ("with CVEs", SEV_RGB["high"], False)], 0, left=24)
    row = ph / max(len(services), 1)
    bh = min(row * 0.65, 5)
    d.set_font("helvetica", "", 6.5)
    for i, s in enumerate(services):
        by = py + i * row + (row - bh) / 2
        d.set_fill_color(*_tint(ACCENT, 0.35))
        d.rect(px, by, max(s["n"] / top * (pw - 8), 0.4), bh, style="F")
        if s["vuln"]:
            d.set_fill_color(*SEV_RGB["high"])
            d.rect(px, by, s["vuln"] / top * (pw - 8), bh, style="F")
        d.set_text_color(*MUTED)
        d.set_xy(px - 24, by + bh / 2 - 1.6)
        d.cell(23, 3.2, _t(_cut(s["label"], 18)), align="R")
        d.set_xy(px + s["n"] / top * (pw - 8) + 0.8, by + bh / 2 - 1.6)
        d.set_text_color(*INK)
        d.cell(8, 3.2, str(s["n"]) + (f"/{s['vuln']}" if s["vuln"] else ""))
    d.set_fill_color(255, 255, 255)


def _pdf_stats(d: _Doc, m: dict):
    """The posture page's four charts, two by two: CVEs and fixes, then attack surface and services."""
    ch = m["charts"]
    w = (d.epw - CHART_W_GAP) / 2
    x1, x2 = d.l_margin, d.l_margin + w + CHART_W_GAP
    sev = [(k, label, SEV_RGB[k], False) for k, label in TREND_SERIES]
    for left, right in (("trend", "fix"), ("surface", "services")):
        y = d.get_y()
        for x, kind in ((x1, left), (x2, right)):
            d.set_draw_color(*LINE)
            d.set_line_width(0.2)
            d.rect(x, y, w, CHART_H)
            inner = (x + 2, y + 1.5, w - 4)
            if kind in ("trend", "surface") and not ch["trend"]:
                _plot_frame(d, *inner, CHART_H, CHART_TITLES[kind], [], 0)
                d.set_xy(inner[0], y + CHART_H / 2)
                d.set_font("helvetica", "I", 8)
                d.set_text_color(*MUTED)
                d.cell(inner[2], 4, NO_TREND, align="C")
            elif kind == "trend":
                _chart_lines(d, *inner, CHART_TITLES["trend"], ch["trend"],
                             [*sev, ("addresses", "Addresses", MUTED, True)])
            elif kind == "surface":
                _chart_lines(d, *inner, CHART_TITLES["surface"], ch["trend"],
                             [("ports", "Open ports", ACCENT, False), ("addresses", "Addresses", MUTED, True)])
            elif not ch[kind]:
                _plot_frame(d, *inner, CHART_H, CHART_TITLES[kind], [], 0)
                d.set_xy(inner[0], y + CHART_H / 2)
                d.set_font("helvetica", "I", 8)
                d.set_text_color(*MUTED)
                d.cell(inner[2], 4, "No CVEs." if kind == "fix" else "No open ports.", align="C")
            elif kind == "fix":
                _chart_fix(d, *inner, ch["fix"])
            else:
                _chart_services(d, *inner, ch["services"])
        d.set_xy(d.l_margin, y + CHART_H + 4)
    d.set_line_width(0.2)


def _height(s: dict) -> float:
    """A rough height (mm) of a host's section, to keep small sections on one page."""
    if not s["vulns"]:
        return 24 + 6 * len(s["notes"]) + 4 * (len(s["services"]) // 4)
    return 40 + 6 * len(s["notes"]) + 5.5 * len(s["services"]) + 16 * len(s["vulns"]) + 9 * len(s["todo"])


def _heading(d: _Doc, text: str):
    d.set_font("helvetica", "B", 9)
    d.set_text_color(*ACCENT)
    d.cell(0, 6, text, new_x="LMARGIN", new_y="NEXT")


def _pdf_host(d: _Doc, m: dict, s: dict, jump: int):
    """One host's section: a large one starts on a new page, a small one stays whole on the current page."""
    many = bool(m["domain_rows"])
    full = d.page_break_trigger - d.t_margin - 8   # a page below the running header
    need = _height(s)
    fresh = d.get_y() <= d.fresh + 1
    if not fresh and (need > full / 2 or need > d.page_break_trigger - d.get_y()):
        d.add_page()
    elif not fresh:
        d.set_draw_color(*LINE)
        d.line(d.l_margin, d.get_y(), d.w - d.r_margin, d.get_y())
        d.ln(2)
    d.set_link(jump, y=d.get_y(), page=d.page)
    title = s["host"] + (f"  ({s['domain']})" if many else "")
    d.start_section(_t(title), level=1)
    y = d.get_y()
    d.set_font("helvetica", "B", 7.5)
    tag = SHORT[s["worst"]]
    tw = d.get_string_width(tag) + 6
    d.set_xy(d.w - d.r_margin - tw, y + 0.8)
    d.set_fill_color(*SEV_RGB.get(s["worst"], MUTED))
    d.set_text_color(255, 255, 255)
    d.cell(tw, 5, _t(tag), fill=True, align="C")
    d.set_fill_color(255, 255, 255)
    d.set_xy(d.l_margin, y)
    d.set_font("helvetica", "B", 11.5)
    d.set_text_color(*INK)
    d.multi_cell(d.epw - tw - 3, 6.5, _t(title), new_x="LMARGIN", new_y="NEXT")
    d.set_font("helvetica", "", 8.5)
    d.set_text_color(*MUTED)
    # a fact breaks only between facts (and between addresses): no-break spaces inside the rest
    nb = "\xa0"
    d.multi_cell(0, 4.3, "   ".join(f"**{_t(k).replace(' ', nb)}:**{nb}" + (_t(v) if k in ("Addresses", "Tags")
                                                                          else _t(v).replace(" ", nb))
                                     for k, v in facts(s, many)[1:]), markdown=True,
                 new_x="LMARGIN", new_y="NEXT")
    d.ln(1)
    for n in s["notes"]:
        d.para(n, 8.5, "I")
    if not s["vulns"]:
        d.para(clean_line(s), 8.5)
        d.ln(1)
        return
    if s["services"]:
        d.grid([*(["Address"] if s["multi"] else []), "Port", "Service", "Product / version", "CVEs"],
               [_svc(s, x) for x in s["services"]],
               (30, 18, 26, 92, 12) if s["multi"] else (20, 30, 116, 12), size=8)
    if m.get("xp"):
        d.grid(["CVE", "Severity", "Score", "Exploit", "Fixed in", "Product / port"],
               [[v["cve"], (v["severity"], v["severity"]), _score(v), xp_marks(v.get("xp") or {}),
                 ", ".join(v["fixes"]) or "no fix yet", _where(s, v)] for v in s["vulns"]],
               (27, 17, 11, 37, 30, 56), sev_col=1, size=7.5)
    else:
        d.grid(["CVE", "Severity", "Score", "Fixed in", "Product / port"],
               [[v["cve"], (v["severity"], v["severity"]), _score(v), ", ".join(v["fixes"]) or "no fix yet",
                 _where(s, v)] for v in s["vulns"]], (28, 18, 12, 40, 80), sev_col=1, size=7.5)
    _heading(d, "References")
    for v in s["vulns"]:   # CVE, summary, then its links as clickable labels, one flowing paragraph per CVE
        d.set_font("helvetica", "B", 7.5)
        d.set_text_color(*INK)
        d.write(3.8, f"{v['cve']}  ")
        d.set_font("helvetica", "", 7.5)
        if v.get("summary"):
            d.write(3.8, _t(_cut(v["summary"], 220)) + "  ")
        d.set_text_color(*ACCENT)
        for i, (label, url) in enumerate([*v["links"], *xp_refs(_xp(m, v))]):
            d.write(3.8, _t((" · " if i else "") + label), link=url)
        d.ln(4.6)
    d.ln(1.5)
    _heading(d, "What to do on this host")
    if s["todo"]:
        d.grid(["Priority", "Action", "Detail"], [[f"P{a['priority']}", a["title"], a["detail"]] for a in s["todo"]],
               (16, 50, 112), size=8)
    else:
        d.para(NO_TODO, 8.5)
    d.ln(2)


def pdf(m: dict) -> bytes:
    """The report as PDF (A4): page 1 the rating, KPIs, summary and recommendations; then the charts, risks,
    hosts and one section per host."""
    d = _Doc(m)
    d.add_page()
    k = m["kpi"]
    d.set_font("helvetica", "", 9)
    d.set_text_color(*MUTED)
    d.cell(0, 5, "SECURITY POSTURE REPORT", new_x="LMARGIN", new_y="NEXT")
    d.set_font("helvetica", "B", 20)
    d.set_text_color(*INK)
    d.cell(0, 11, _t(m["title"]), new_x="LMARGIN", new_y="NEXT")
    d.set_font("helvetica", "", 9)
    d.set_text_color(*MUTED)
    d.cell(0, 5, _t(_byline(m)), new_x="LMARGIN", new_y="NEXT")
    d.ln(4)
    d.set_fill_color(*SEV_RGB.get(m["worst"], MUTED))
    d.set_text_color(255, 255, 255)
    d.set_font("helvetica", "B", 12)
    d.cell(0, 10, _t(f"  Overall risk: {m['rating']}"), fill=True, new_x="LMARGIN", new_y="NEXT")
    d.set_fill_color(255, 255, 255)   # tables would inherit the banner's fill
    d.ln(4)
    tiles = [("Critical", k["critical"], "critical"), ("High", k["high"], "high"),
             ("Medium", m["by_sev"]["medium"], "medium"), ("Low", m["by_sev"]["low"], "low"),
             ("Fixable", f"{k['fixable']}/{k['cves']}", ""), ("Open ports", k["open_ports"], ""),
             ("Addresses", k["addresses"], "")]
    w = (d.w - d.l_margin - d.r_margin) / len(tiles)
    y = d.get_y()
    d.set_draw_color(*LINE)
    for i, (label, val, sev) in enumerate(tiles):
        x = d.l_margin + i * w
        d.rect(x + 0.8, y, w - 1.6, 16)
        d.set_xy(x, y + 1.5)
        d.set_font("helvetica", "B", 14)
        d.set_text_color(*(SEV_RGB[sev] if sev else INK))
        d.cell(w, 7, _t(val), align="C")
        d.set_xy(x, y + 9)
        d.set_font("helvetica", "", 7.5)
        d.set_text_color(*MUTED)
        d.cell(w, 5, label, align="C")
    d.set_xy(d.l_margin, y + 20)
    h_ = heads(m)
    d.h1(h_["Executive summary"])
    for line in summary_lines(m):
        d.para(line)
    d.h1(h_["Recommendations"])
    if m["actions"]:
        d.grid(["Priority", "Action", "Detail"],
               [[f"P{a['priority']}", a["title"], a["detail"]] for a in m["actions"]], (16, 46, 116))
    else:
        d.para("No action needed on the current results.")
    if d.get_y() > d.page_break_trigger - 2 * CHART_H - 25:   # the four charts stay together
        d.add_page()
    d.h1(h_["Statistics"])
    _pdf_stats(d, m)
    d.h1(h_["Top risks"])
    if m["top"]:
        if m.get("xp"):
            d.grid(["CVE", "Severity", "Exploit", "Product", "Fixed in", "Hosts"],
                   [[v["cve"], (_sev(v), v["severity"]), xp_marks(v["xp"]), ", ".join(v["products"]),
                     ", ".join(v["fixes"]) or "no fix yet", _more(_names(v), 6)] for v in m["top"]],
                   (28, 20, 30, 36, 26, 38), sev_col=1)
        else:
            d.grid(["CVE", "Severity", "Product", "Fixed in", "Hosts"],
                   [[v["cve"], (_sev(v), v["severity"]), ", ".join(v["products"]),
                     ", ".join(v["fixes"]) or "no fix yet", _more(_names(v), 6)] for v in m["top"]],
                   (30, 22, 44, 32, 50), sev_col=1)
    else:
        d.para("No critical or high vulnerabilities.")
    if m["domain_rows"]:
        d.h1(h_["Domains"])
        d.grid(["Domain", "Rating", "CVEs (c/h)", "Fixable", "High+ addr.", "Ports"],
               [_dom_cells(x) for x in m["domain_rows"]], (62, 26, 24, 22, 24, 20), sev_col=1)
    d.h1(h_["Hosts"])
    jumps = [d.add_link() for _ in m["sections"]]
    d.grid(["Host name", "Addresses", "Rating", "CVEs (c/h)", "Fixable", "Ports", "Last scan"],
           [[h["host"], _ips(h["ips"]), (SHORT[h["worst"]], h["worst"]),
             f"{h['cves']} ({h['sev_n'].get('critical', 0)}/{h['sev_n'].get('high', 0)})", h["fixable"],
             h["open_ports"], h["last"][:10] or "never"] for h in m["sections"]],
           (44, 44, 22, 18, 13, 11, 26), sev_col=2, jumps=jumps)
    if m["sections"]:
        d.add_page()
        d.h1(h_["Host findings"])
        d.fresh = d.get_y()   # the first host follows its heading on this page
    for x, jump in zip(m["sections"], jumps, strict=True):
        _pdf_host(d, m, x, jump)
    d.h1(h_["Scope and method"])
    for line in _method(m):
        d.para(line, 9)
    return bytes(d.output())


def filename(m: dict, ext: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in ".-" else "-" for ch in m["subject"])
    return f"posture-report-{safe}-{m['created'][:10]}.{ext}"
