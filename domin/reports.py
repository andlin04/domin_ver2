"""Posture reports: an executive and technical report on picked host names of one domain, as Markdown or PDF.

build() gathers the facts once (current posture results of the picked names' addresses); markdown() and pdf()
only lay them out, so both files say the same thing. Recommendations are rules on those facts, never free text."""

from __future__ import annotations

import re
import sqlite3
from datetime import datetime

from fpdf import FPDF
from fpdf.fonts import FontFace

from . import cve, posture

# services that should rarely face the internet: named in the attack-surface recommendation when open
RISKY_PORTS = {21: "FTP", 23: "Telnet", 69: "TFTP", 111: "RPC", 135: "MS-RPC", 139: "NetBIOS", 445: "SMB",
               1433: "MS SQL", 1521: "Oracle DB", 2049: "NFS", 2375: "Docker API", 3306: "MySQL", 3389: "RDP",
               5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached",
               27017: "MongoDB"}
RATING = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "unknown": "Unrated",
          "none": "No known vulnerabilities", "": "Not assessed"}
TOP_RISKS = 10
MAX_HOSTS = 500


def build(conn: sqlite3.Connection, domain: str, picked: list[str], by: str = "") -> dict:
    """The report's facts for the picked host names of `domain` (unknown names are ignored)."""
    want = set(picked)
    names = [h for h in posture.host_list(conn, domain) if h["host"] in want][:MAX_HOSTS]
    ips = {ip for h in names for ip in h["ips"]}
    rep = posture.report([r for r in posture.current(conn, domain) if r["ip"] in ips])
    hosts = posture.with_results(names, rep["rows"])
    hosts.sort(key=lambda h: (h["rank"], *(-h["sev_n"].get(s, 0) for s in posture.SEVERITIES), h["host"]))
    rows = rep["rows"]
    done = [r for r in rows if r["status"] == "done"]
    worst = next((s for s in (*posture.SEVERITIES, "none") if any(r["worst"] == s for r in done)), "")
    finished = sorted(r["finished"] for r in done if r.get("finished"))
    return {
        "domain": domain, "by": by, "created": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "hosts": hosts, "rows": rows, "vulns": rep["vulns"], "kpi": rep["kpi"], "by_sev": rep["by_sev"],
        "rating": RATING[worst], "worst": worst,
        "period": (finished[0][:10], finished[-1][:10]) if finished else ("", ""),
        "profiles": sorted({r.get("profile") or "default" for r in done}),
        "never": [h["host"] for h in hosts if not h["results"]],
        "top": [v for v in rep["vulns"] if v["severity"] in ("critical", "high")][:TOP_RISKS],
        "actions": actions(rep["vulns"], rows, hosts),
        "source": cve.SOURCE,
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
        out.append({"priority": 1, "title": f"Update {p} to {target} or later",
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
    first = [a["title"] for a in m["actions"] if a["priority"] == 1][:3]
    if first:
        lines.append("First actions: " + "; ".join(first) + ".")
    return lines


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
METHOD = ("Method: network service and version detection (scan profiles: {profiles}), matched against known"
          " vulnerabilities ({source}). Scans: {period}.")
LIMITS = ("Limits: matches are by product version; vendors that backport fixes can show false positives, and services"
          " that hide their version can hide vulnerabilities. Addresses that answered on no port are not assessed.")


def _method(m: dict) -> list[str]:
    return [SCOPE.format(n=len(m["hosts"]), domain=m["domain"]),
            METHOD.format(profiles=", ".join(m["profiles"]) or "none", source=m["source"], period=_period(m)),
            LIMITS] + ([f"Never scanned: {', '.join(m['never'])}."] if m["never"] else [])


def markdown(m: dict) -> str:
    """The report as Markdown."""
    k = m["kpi"]
    md = [f"# Security posture report: {m['domain']}", "", _byline(m), "",
          "## 1. Executive summary", "", *summary_lines(m), "",
          "| Overall risk | Critical | High | Medium | Low | Fixable | Open ports | Addresses |",
          "|---|---:|---:|---:|---:|---:|---:|---:|",
          f"| **{m['rating']}** | {k['critical']} | {k['high']} | {m['by_sev']['medium']} | {m['by_sev']['low']}"
          f" | {k['fixable']}/{k['cves']} | {k['open_ports']} | {k['addresses']} |", "",
          "## 2. Recommendations", ""]
    if m["actions"]:
        md += [f"{i}. **P{a['priority']} · {a['title']}.** {a['detail']}" for i, a in enumerate(m["actions"], 1)]
    else:
        md.append("No action needed on the current results.")
    md += ["", "## 3. Top risks", ""]
    if m["top"]:
        md += ["| CVE | Severity | Product | Fixed in | Hosts |", "|---|---|---|---|---|"]
        md += [f"| [{v['cve']}]({posture.links(v)[0][1]}) | {_sev(v)} | {_cell(', '.join(v['products']))} |"
               f" {_cell(', '.join(v['fixes']) or 'no fix yet')} | {_cell(', '.join(_names(v)))} |" for v in m["top"]]
    else:
        md.append("No critical or high vulnerabilities.")
    md += ["", "## 4. Hosts", "",
           "| Host name | Addresses | Rating | CVEs (critical/high) | Fixable | Open ports | Last scan |",
           "|---|---|---|---:|---:|---:|---|"]
    md += [f"| {h['host']} | {', '.join(h['ips'])} | {RATING[h['worst']]} | {h['cves']}"
           f" ({h['sev_n'].get('critical', 0)}/{h['sev_n'].get('high', 0)}) | {h['fixable']} | {h['open_ports']}"
           f" | {h['last'] or 'never'} |" for h in m["hosts"]]
    md += ["", "## 5. Technical findings", ""]
    for r in m["rows"]:
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
        md += [f"- **{v['cve']}** ({_sev(v)}; fixed in {', '.join(v['fixes']) or 'no fix yet'}):"
               f" {_cell(_cut(v.get('summary'), 300))}" for v in r["vulns"]]
        md.append("")
    md += ["## 6. Scope and method", "", *(f"- {x}" for x in _method(m)), ""]
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

    def grid(self, head: list[str], rows: list[list], widths: tuple, sev_col: int | None = None, size: float = 8.5):
        """A table; a (label, severity) value in sev_col is printed bold in the severity's colour."""
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
    d.h1("1. Executive summary")
    for line in summary_lines(m):
        d.para(line)
    d.h1("2. Recommendations")
    if m["actions"]:
        d.grid(["Priority", "Action", "Detail"],
               [[f"P{a['priority']}", a["title"], a["detail"]] for a in m["actions"]], (16, 46, 116))
    else:
        d.para("No action needed on the current results.")
    d.h1("3. Top risks")
    if m["top"]:
        d.grid(["CVE", "Severity", "Product", "Fixed in", "Hosts"],
               [[v["cve"], (_sev(v), v["severity"]), ", ".join(v["products"]), ", ".join(v["fixes"]) or "no fix yet",
                 _more(_names(v), 6)] for v in m["top"]], (30, 22, 44, 32, 50), sev_col=1)
    else:
        d.para("No critical or high vulnerabilities.")
    d.h1("4. Hosts")
    d.grid(["Host name", "Addresses", "Rating", "CVEs (c/h)", "Fixable", "Ports", "Last scan"],
           [[h["host"], _ips(h["ips"]), (SHORT[h["worst"]], h["worst"]),
             f"{h['cves']} ({h['sev_n'].get('critical', 0)}/{h['sev_n'].get('high', 0)})", h["fixable"],
             h["open_ports"], h["last"][:10] or "never"] for h in m["hosts"]],
           (44, 44, 22, 18, 13, 11, 26), sev_col=2)
    if m["rows"]:
        d.add_page()
        d.h1("5. Technical findings")
    for r in m["rows"]:
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
        if r["vulns"]:
            d.grid(["CVE", "Severity", "Fixed in", "Summary"],
                   [[v["cve"], (_sev(v), v["severity"]), ", ".join(v["fixes"]) or "no fix yet",
                     _cut(v.get("summary"), 220)] for v in r["vulns"]], (28, 22, 30, 98), sev_col=1, size=7.5)
        d.ln(2)
    d.h1("6. Scope and method")
    for line in _method(m):
        d.para(line, 9)
    return bytes(d.output())


def filename(m: dict, ext: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in ".-" else "-" for ch in m["domain"])
    return f"posture-report-{safe}-{m['created'][:10]}.{ext}"
