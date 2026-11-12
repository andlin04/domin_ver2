"""CVE lookups for the security / posture engine.

Sources: OSV.dev for packages (Debian, Ubuntu, PyPI, Go, npm, ...)
and NVD (by CPE) for products that OSV does not carry. Both are updated continuously upstream as advisories land;
NVD publishes within hours and OSV mirrors the distro and ecosystem feeds on a similar cadence.

To keep repeat scans fast and to work without reaching the internet on every run, this instance keeps a local CVE
database: a cache keyed by the target, holding the findings and when they were fetched.

  own     the instance downloads and maintains that database itself (queries OSV / NVD and stores the results),
          refreshing an entry older than `ttl_days`.
  shared  it reads a database maintained elsewhere (DOMIN_CVE_DB_PATH), read-only, and never queries the network;
          a target that is not already in that database comes back empty with a note.

Nothing here probes a target. Callers pass a product/version (CPE) or a package (ecosystem + name + version); the
posture scope in Settings governs which hosts a future fingerprinting step may feed in.
"""
from __future__ import annotations

import json
import logging
import math
import re
import time
from dataclasses import dataclass
from pathlib import Path

import httpx

log = logging.getLogger("domin.cve")

OSV = "https://api.osv.dev/v1"
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SOURCE = "OSV.dev + NVD"
SEVERITIES = ("critical", "high", "medium", "low", "unknown")
FORMAT = 4   # cache entry format; 2 = NVD fixed versions, 3 = "after X", 4 = only the scanned version's range
#              (older entries are refetched once)

_CVSS3 = {"AV": {"N": .85, "A": .62, "L": .55, "P": .2}, "AC": {"L": .77, "H": .44}, "UI": {"N": .85, "R": .62},
          "CIA": {"H": .56, "L": .22, "N": 0.0}}


def cvss3_score(vector: str) -> float | None:
    """Base score from a CVSS v3.x vector string (the same arithmetic the vuln watch uses)."""
    try:
        m = dict(p.split(":") for p in vector.split("/")[1:])
        changed = m["S"] == "C"
        pr = {"N": .85, "L": .68 if changed else .62, "H": .5 if changed else .27}[m["PR"]]
        iss = 1 - (1 - _CVSS3["CIA"][m["C"]]) * (1 - _CVSS3["CIA"][m["I"]]) * (1 - _CVSS3["CIA"][m["A"]])
        impact = 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15 if changed else 6.42 * iss
        if impact <= 0:
            return 0.0
        expl = 8.22 * _CVSS3["AV"][m["AV"]] * _CVSS3["AC"][m["AC"]] * pr * _CVSS3["UI"][m["UI"]]
        raw = min(1.08 * (impact + expl), 10) if changed else min(impact + expl, 10)
        return math.ceil(round(raw * 100000) / 10000) / 10
    except (KeyError, ValueError):
        return None


def band(score: float | None) -> str:
    if score is None:
        return "unknown"
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"


def rank(severity: str, score: float | None) -> tuple[int, float]:
    """Sort key, most severe first."""
    idx = SEVERITIES.index(severity) if severity in SEVERITIES else len(SEVERITIES)
    return (idx, -(score or 0))


# ---------------------------------------------------------------- source queries

REFS = 8   # reference links kept per finding


def _finding(cve: str, severity: str, score: float | None, fixed: str | None, summary: str, url: str,
             source: str, vector: str = "", published: str = "", cwe: list[str] | None = None,
             refs: list[str] | None = None, xrefs: list[str] | None = None) -> dict:
    """One finding. vector = CVSS vector string, published = YYYY-MM-DD, cwe = weakness ids, refs = reference URLs
    (https only, at most REFS): the detail shown when a CVE row is opened; xrefs = those tagged "Exploit" by NVD."""
    return {"cve": cve, "severity": severity, "score": score, "fixed": fixed,
            "summary": " ".join((summary or "").split())[:1000], "url": url, "source": source,
            "vector": vector or "", "published": (published or "")[:10], "cwe": list(dict.fromkeys(cwe or [])),
            "refs": [r for r in dict.fromkeys(refs or []) if r.startswith("https://")][:REFS],
            "xrefs": [r for r in dict.fromkeys(xrefs or []) if r.startswith("https://")][:REFS]}


def osv_cves(client: httpx.Client, ecosystem: str, name: str, version: str) -> list[dict]:
    """Known vulnerabilities for one package version from OSV.dev."""
    q = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
    rec = client.post(f"{OSV}/query", json=q).raise_for_status().json()
    out = []
    for v in rec.get("vulns") or []:
        vid = v.get("id", "")
        cves = [a for a in v.get("aliases") or [] if a.startswith("CVE-")]
        sev = v.get("severity") or []
        score = next((cvss3_score(s.get("score", "")) for s in sev if s.get("type", "").startswith("CVSS_V3")), None)
        if score is not None:
            severity = band(score)
        else:
            ghsa = str((v.get("database_specific") or {}).get("severity", "")).lower()
            severity = {"moderate": "medium"}.get(ghsa, ghsa if ghsa in SEVERITIES else "unknown")
        fixed = []
        for a in v.get("affected") or []:
            pkg = a.get("package") or {}
            if pkg.get("ecosystem") == ecosystem and pkg.get("name") == name:
                fixed += [e["fixed"] for r in a.get("ranges") or [] for e in r.get("events") or [] if "fixed" in e]
        vector = next((s.get("score", "") for s in sev if s.get("type", "").startswith("CVSS_V3")), "")
        out.append(_finding(cves[0] if cves else vid, severity, score, " / ".join(dict.fromkeys(fixed)) or None,
                            v.get("summary") or v.get("details") or "", f"https://osv.dev/vulnerability/{vid}", "OSV",
                            vector=vector, published=v.get("published", ""),
                            cwe=(v.get("database_specific") or {}).get("cwe_ids") or [],
                            refs=[r.get("url", "") for r in v.get("references") or []]))
    return out


def version_key(v: str) -> tuple:
    """Sortable key for a version string: number and letter runs ("8.4p1" -> 8, 4, p, 1)."""
    return tuple((0, int(x), "") if x.isdigit() else (1, 0, x) for x in re.findall(r"[0-9]+|[a-z]+", v.lower()))


def in_range(m: dict, version: str) -> bool:
    """Does an NVD cpeMatch range (versionStart/End Including/Excluding) contain version?"""
    k = version_key(version)
    checks = (("versionStartIncluding", lambda b: k >= b), ("versionStartExcluding", lambda b: k > b),
              ("versionEndIncluding", lambda b: k <= b), ("versionEndExcluding", lambda b: k < b))
    return all(ok(version_key(m[f])) for f, ok in checks if m.get(f))


def nvd_fixed(cve: dict, part: str, vendor: str, product: str, version: str = "") -> list[str]:
    """Fixed versions from an NVD record's vulnerable CPE ranges for this product: versionEndExcluding is the first
    fixed version (2.4.67 for "before 2.4.67"); a range closed with versionEndIncluding only names the last affected
    one, so the fix is "after 2.4.55" (NVD does not say which later version). With several ranges (one per release
    branch: nginx 1.26.x fixed in 1.26.3, 1.27.x in 1.27.4) only those containing version count; none does: all."""
    prefix = f"cpe:2.3:{part}:{vendor}:{product}:".lower()
    ranges = [m for c in cve.get("configurations") or [] for n in c.get("nodes") or [] for m in n.get("cpeMatch") or []
              if m.get("vulnerable") and str(m.get("criteria", "")).lower().startswith(prefix)
              and (m.get("versionEndExcluding") or m.get("versionEndIncluding"))]
    if version and (own := [m for m in ranges if in_range(m, version)]):
        ranges = own
    found = [m["versionEndExcluding"] if m.get("versionEndExcluding") else f"after {m['versionEndIncluding']}"
             for m in ranges]
    return list(dict.fromkeys(found))


def nvd_cves(client: httpx.Client, part: str, vendor: str, product: str, version: str,
             api_key: str = "") -> list[dict]:
    """Known vulnerabilities for a product version from NVD, matched by CPE."""
    cpe = f"cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    headers = {"User-Agent": "domin-security"}
    if api_key:
        headers["apiKey"] = api_key
    resp = client.get(NVD, params={"virtualMatchString": cpe}, headers=headers).raise_for_status().json()
    out = []
    for v in resp.get("vulnerabilities") or []:
        cve = v.get("cve") or {}
        score, vector = None, ""
        for metric in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
            entries = (cve.get("metrics") or {}).get(metric) or []
            if entries:
                score = entries[0].get("cvssData", {}).get("baseScore")
                vector = entries[0].get("cvssData", {}).get("vectorString", "")
                break
        cwe = [d["value"] for w in cve.get("weaknesses") or [] for d in w.get("description") or []
               if str(d.get("value", "")).startswith("CWE-")]
        desc = next((d["value"] for d in cve.get("descriptions") or [] if d.get("lang") == "en"), "")
        cid = cve.get("id", "?")
        fixed = " / ".join(nvd_fixed(cve, part, vendor, product, version)) or None
        out.append(_finding(cid, band(score), score, fixed, desc,
                            f"https://nvd.nist.gov/vuln/detail/{cid}", "NVD", vector=vector,
                            published=cve.get("published", ""), cwe=cwe,
                            refs=[r.get("url", "") for r in cve.get("references") or []],
                            xrefs=[r.get("url", "") for r in cve.get("references") or []
                                   if "Exploit" in (r.get("tags") or [])]))
    return out


def query_source(client: httpx.Client, target: dict, api_key: str = "") -> list[dict]:
    """Live query for one target against its source, newest/worst first."""
    if target["kind"] == "osv":
        found = osv_cves(client, target["ecosystem"], target["name"], target["version"])
    else:
        found = nvd_cves(client, target.get("part", "a"), target["vendor"], target["product"], target["version"],
                         api_key)
    seen, deduped = set(), []
    for f in sorted(found, key=lambda x: rank(x["severity"], x["score"])):
        if f["cve"] not in seen:
            seen.add(f["cve"])
            deduped.append(f)
    return deduped


# ---------------------------------------------------------------- local database

def target_key(target: dict) -> str:
    if target["kind"] == "osv":
        return f"osv|{target['ecosystem']}|{target['name']}|{target['version']}".lower()
    return f"cpe|{target.get('part', 'a')}|{target['vendor']}|{target['product']}|{target['version']}".lower()


def target_label(target: dict) -> str:
    if target["kind"] == "osv":
        return f"{target['name']} {target['version']} ({target['ecosystem']})"
    return f"{target['vendor']}:{target['product']} {target['version']}"


@dataclass
class Database:
    """The local CVE database. `own` reads and writes `path`; `shared` only reads it."""
    mode: str
    path: Path
    ttl_days: int = 7

    def _load(self) -> dict:
        try:
            return json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists() else {}
        except (OSError, ValueError):
            return {}

    def entry(self, key: str) -> dict | None:
        return self._load().get(key)

    def fresh(self, entry: dict | None) -> bool:
        return (bool(entry) and entry.get("format", 1) == FORMAT
                and (time.time() - entry.get("fetched", 0)) < self.ttl_days * 86400)

    def store(self, key: str, findings: list[dict]) -> None:
        if self.mode != "own":
            return
        data = self._load()
        data[key] = {"fetched": int(time.time()), "format": FORMAT, "findings": findings}
        tmp = self.path.with_name(self.path.name + ".tmp")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(data), encoding="utf-8")
        tmp.replace(self.path)

    def size(self) -> int:
        return len(self._load())


def lookup(db: Database, target: dict, client: httpx.Client | None = None, api_key: str = "") -> dict:
    """CVEs for one target from the local database, querying the source when allowed.

    Returns {findings, cached, note}. In `own` mode a miss or a stale entry triggers a live query (when a client is
    available); in `shared` mode only what the database already holds is returned.
    """
    key = target_key(target)
    entry = db.entry(key)
    if db.mode == "shared":
        if entry is None:
            return {"findings": [], "cached": False, "note": "not in the shared CVE database"}
        return {"findings": entry["findings"], "cached": True, "note": ""}
    if db.fresh(entry):
        return {"findings": entry["findings"], "cached": True, "note": ""}
    if client is None:
        if entry is not None:
            return {"findings": entry["findings"], "cached": True, "note": "served from the local database (offline)"}
        return {"findings": [], "cached": False, "note": "no network and nothing cached for this target"}
    try:
        findings = query_source(client, target, api_key)
    except httpx.HTTPError as exc:
        log.warning("cve source %s: %s", key, exc)
        if entry is not None:
            return {"findings": entry["findings"], "cached": True, "note": f"source unreachable ({exc}); cached result"}
        return {"findings": [], "cached": False, "note": f"source unreachable: {exc}"}
    db.store(key, findings)
    return {"findings": findings, "cached": False, "note": ""}


_CPE_SAFE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


def parse_target(form: dict[str, str]) -> dict:
    """A scan form into a target dict, or raise ValueError with a message for the user."""
    kind = form.get("kind", "cpe")
    version = (form.get("version") or "").strip()
    if not version or len(version) > 64:
        raise ValueError("Give a version to check.")
    if kind == "osv":
        eco = (form.get("ecosystem") or "").strip()
        name = (form.get("name") or "").strip()
        if not eco or not name or len(name) > 128:
            raise ValueError("Give an ecosystem and a package name.")
        return {"kind": "osv", "ecosystem": eco, "name": name, "version": version}
    vendor = (form.get("vendor") or "").strip().lower()
    product = (form.get("product") or "").strip().lower()
    part = form.get("part", "a")
    if part not in ("a", "o", "h"):
        raise ValueError("Part must be a (application), o (OS) or h (hardware).")
    if not _CPE_SAFE.match(vendor or "") or not _CPE_SAFE.match(product or ""):
        raise ValueError("Vendor and product must be lower-case CPE tokens (letters, digits, . _ -).")
    return {"kind": "cpe", "part": part, "vendor": vendor, "product": product, "version": version}
