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


def build(conn: sqlite3.Connection, picks: dict[str, list[str] | None], by: str = "") -> dict:
    """The report's facts for picked domains: {domain: picked host names, or None for all of them}. Unknown names
    are ignored. Several domains add a per-domain table, and the technical findings keep only the addresses with
    CVEs, errors or notes (a clean address is a row in the host table)."""
    names: list[dict] = []
    raw: list[dict] = []
    for dom, want in list(picks.items())[:MAX_DOMAINS]:
        found = [h for h in posture.host_list(conn, dom) if want is None or h["host"] in set(want)]
        ips = {ip for h in found for ip in h["ips"]}
        raw += [r for r in posture.current(conn, dom) if r["ip"] in ips]
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
    return {
        "domain": f"{len(doms)} domains" if many else (doms[0] if doms else ""), "domains": doms,
        "domain_rows": posture.domain_summary(rows) if many else [],
        "details": [r for r in rows if r["vulns"] or r.get("error") or r.get("note")] if many else rows,
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


def actions(vulns: list[dict], rows: list[dict], hosts: list[dict]) -> list[dict]:
    """Prioritised recommendations: patch (critical/high with a published fix, per product), mitigate (critical/high
    without one), reduce exposure (services that rarely belong on the internet), then medium/low patching and
    coverage gaps. Each: priority (1 = first), title, detail."""
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
                              f" Hosts: {_more(sorted(g['hosts']), 8)}."})
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
                              + "; ".join(f"{k} on {_more(sorted(h), 4)}" for k, h in sorted(risky.items()))
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
              " from each domain's latest inventory scan. Technical findings list the addresses with vulnerabilities,"
              " errors or notes.")


def heads(m: dict) -> dict[str, str]:
    """Section titles, numbered: the Domains section only in a report on several domains."""
    names = ["Executive summary", "Recommendations", "Top risks", *(["Domains"] if m["domain_rows"] else []),
             "Hosts", "Technical findings", "Scope and method"]
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
    return [scope,
            METHOD.format(profiles=", ".join(m["profiles"]) or "none", source=m["source"], period=_period(m)),
            *xp, LIMITS] +([f"Never scanned: {', '.join(m['never'])}."] if m["never"] else [])


def markdown(m: dict) -> str:
    """The report as Markdown."""
    k, h_ = m["kpi"], heads(m)
    md = [f"# Security posture report: {m['domain']}", "", _byline(m), "",
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
    md += ["", f"## {h_['Top risks']}", ""]
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
    md += [f"| {h['host']} | {', '.join(h['ips'])} | {RATING[h['worst']]} | {h['cves']}"
           f" ({h['sev_n'].get('critical', 0)}/{h['sev_n'].get('high', 0)}) | {h['fixable']} | {h['open_ports']}"
           f" | {h['last'] or 'never'} |" for h in m["hosts"]]
    md += ["", f"## {h_['Technical findings']}", ""]
    for r in m["details"]:
        md += [f"### {r['ip']} ({(r.get('hosts') or '').replace(',', ', ') or 'no name'})", "",
               _status(r), ""]
        for note in (r.get("note"), r.get("error") and f"Error: {r['error']}"):
            if note:
                md += [f"> {_cell(note)}", ""]
        if r["services"]:
            md += ["| Port | Service | Product / version | CVEs |", "|---|---|---|---:|"]
            md += [f"| {s['port']}/{s.get('proto') or 'tcp'} | {_cell(s.get('service') or '')} |"
                   f" {_cell(' '.join(x for x in (s.get('product'), s.get('version')) if x))} |"
                   f" {len(s.get('findings') or [])} |" for s in r["services"]]
            md.append("")
        for v in r["vulns"]:
            md.append(f"- **{v['cve']}** ({_sev(v)}; fixed in {', '.join(v['fixes']) or 'no fix yet'}):"
                      f" {_cell(_cut(v.get('summary'), 300))}")
            if marks := xp_marks(_xp(m, v)):
                md.append(f"  - Exploit: {marks}")
            if refs := xp_refs(_xp(m, v)):
                md.append("  - References: " + ", ".join(f"[{_cell(label)}]({url})" for label, url in refs))
        md.append("")
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
        self.set_title(_t(f"Security posture report: {m['domain']}"))
        self.set_creator("domin")

    def header(self):
        if self.page_no() == 1:
            return
        self.set_font("helvetica", "", 8)
        self.set_text_color(*MUTED)
        self.cell(0, 6, _t(f"Security posture report · {self.m['domain']} · {self.m['created']}"))
        self.ln(8)

    def footer(self):
        self.set_y(-12)
        self.set_font("helvetica", "", 8)
        self.set_text_color(*MUTED)
        self.cell(0, 6, f"Confidential · page {self.page_no()}/{{nb}}", align="R")

    def h1(self, text: str):
        if self.get_y() > self.page_break_trigger - 35:   # never a heading alone at the foot of a page
            self.add_page()
        self.ln(3)
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
             links: int | None = None):
        """A table; a (label, severity) value in sev_col is printed bold in the severity's colour; the URL in column
        links is clickable."""
        self.set_font("helvetica", "", size)
        self.set_text_color(*INK)
        self.set_draw_color(*LINE)
        head_style = FontFace(emphasis="BOLD", color=(255, 255, 255), fill_color=ACCENT)
        with self.table(col_widths=widths, headings_style=head_style, line_height=size * 0.55, text_align="LEFT",
                        borders_layout="HORIZONTAL_LINES", padding=1.2, cell_fill_color=ZEBRA,
                        cell_fill_mode="ROWS") as t:
            t.row([_t(x) for x in head])
            for r in rows:
                row = t.row()
                for i, val in enumerate(r):
                    if i == sev_col and isinstance(val, tuple):
                        row.cell(_t(val[0]), style=FontFace(emphasis="BOLD", color=SEV_RGB.get(val[1], INK)))
                    elif i == links:
                        row.cell(_t(val), link=str(val), style=FontFace(color=ACCENT))
                    else:
                        row.cell(_t(val))
        self.ln(3)


def pdf(m: dict) -> bytes:
    """The report as PDF (A4): page 1 the rating, KPIs, summary and recommendations; then risks, hosts, details."""
    d = _Doc(m)
    d.add_page()
    k = m["kpi"]
    d.set_font("helvetica", "", 9)
    d.set_text_color(*MUTED)
    d.cell(0, 5, "SECURITY POSTURE REPORT", new_x="LMARGIN", new_y="NEXT")
    d.set_font("helvetica", "B", 20)
    d.set_text_color(*INK)
    d.cell(0, 11, _t(m["domain"]), new_x="LMARGIN", new_y="NEXT")
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
    d.grid(["Host name", "Addresses", "Rating", "CVEs (c/h)", "Fixable", "Ports", "Last scan"],
           [[h["host"], _ips(h["ips"]), (SHORT[h["worst"]], h["worst"]),
             f"{h['cves']} ({h['sev_n'].get('critical', 0)}/{h['sev_n'].get('high', 0)})", h["fixable"],
             h["open_ports"], h["last"][:10] or "never"] for h in m["hosts"]],
           (44, 44, 22, 18, 13, 11, 26), sev_col=2)
    if m["details"]:
        d.add_page()
        d.h1(h_["Technical findings"])
    for r in m["details"]:
        d.set_font("helvetica", "B", 10.5)
        d.set_text_color(*INK)
        d.multi_cell(0, 6, _t(f"{r['ip']}  ({(r.get('hosts') or '').replace(',', ', ') or 'no name'})"),
                     new_x="LMARGIN", new_y="NEXT")
        d.set_font("helvetica", "", 8.5)
        d.set_text_color(*MUTED)
        d.cell(0, 5, _t(_status(r)), new_x="LMARGIN", new_y="NEXT")
        for note in (r.get("note"), r.get("error") and f"Error: {r['error']}"):
            if note:
                d.para(note, 8.5, "I")
        if r["services"]:
            d.grid(["Port", "Service", "Product / version", "CVEs"],
                   [[f"{s['port']}/{s.get('proto') or 'tcp'}", s.get("service") or "",
                     " ".join(x for x in (s.get("product"), s.get("version")) if x), len(s.get("findings") or [])]
                    for s in r["services"]], (20, 30, 116, 12))
        if r["vulns"] and m.get("xp"):
            d.grid(["CVE", "Severity", "Fixed in", "Exploit", "Summary"],
                   [[v["cve"], (_sev(v), v["severity"]), ", ".join(v["fixes"]) or "no fix yet", xp_marks(v["xp"]),
                     _cut(v.get("summary"), 180)] for v in r["vulns"]], (26, 20, 26, 30, 76), sev_col=1, size=7.5)
            refs = [[v["cve"], label, url] for v in r["vulns"] for label, url in xp_refs(v["xp"])]
            if refs:
                d.grid(["CVE", "Exploit reference", "Link"], refs, (26, 60, 92), size=7, links=2)
        elif r["vulns"]:
            d.grid(["CVE", "Severity", "Fixed in", "Summary"],
                   [[v["cve"], (_sev(v), v["severity"]), ", ".join(v["fixes"]) or "no fix yet",
                     _cut(v.get("summary"), 220)] for v in r["vulns"]], (28, 22, 30, 98), sev_col=1, size=7.5)
        d.ln(2)
    d.h1(h_["Scope and method"])
    for line in _method(m):
        d.para(line, 9)
    return bytes(d.output())


def filename(m: dict, ext: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in ".-" else "-" for ch in m["domain"])
    return f"posture-report-{safe}-{m['created'][:10]}.{ext}"
