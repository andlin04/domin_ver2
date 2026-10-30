"""Single-domain lookups: registration data (RDAP) and e-mail security records (MX, SPF, DMARC, MTA-STS, DNSSEC)."""
from __future__ import annotations

import re

import dns.exception
import dns.resolver
import httpx

SPF_LOOKUPS = re.compile(r"^(?:[+\-~?]?)(include:|a\b|a:|mx\b|mx:|ptr|exists:|redirect=)", re.I)


def rdap(domain: str, client: httpx.Client) -> dict:
    """Registration data via rdap.org, which redirects to the registry's RDAP server (the successor of whois)."""
    r = client.get(f"https://rdap.org/domain/{domain}", timeout=20)
    if r.status_code == 404:
        return {"found": False}
    r.raise_for_status()
    data = r.json()
    events = {e.get("eventAction"): e.get("eventDate", "")[:10] for e in data.get("events", [])}
    entities = []
    for ent in data.get("entities", []):
        name = ""
        for item in (ent.get("vcardArray") or [None, []])[1]:
            if item and item[0] in ("fn", "org") and item[3]:
                name = item[3]
                break
        entities.append({"roles": ent.get("roles", []), "name": name, "handle": ent.get("handle", "")})
    return {"found": True, "name": data.get("ldhName", domain).lower(), "status": data.get("status", []),
            "registered": events.get("registration", ""), "changed": events.get("last changed", ""),
            "expires": events.get("expiration", ""),
            "nameservers": sorted(n.get("ldhName", "").lower() for n in data.get("nameservers", [])),
            "dnssec": bool((data.get("secureDNS") or {}).get("delegationSigned")), "entities": entities,
            "source": str(r.url)}


def _txt(resolver: dns.resolver.Resolver, name: str) -> list[str]:
    try:
        return [b"".join(a.strings).decode("utf-8", "replace") for a in resolver.resolve(name, "TXT")]
    except (dns.exception.DNSException, OSError):
        return []


def _tags(record: str) -> dict:
    return {k.strip().lower(): v.strip() for k, _, v in (p.partition("=") for p in record.split(";")) if k.strip()}


def email_security(domain: str, resolver: dns.resolver.Resolver | None = None) -> dict:
    """Each check: status ok | warn | bad, the record, and findings in plain words."""
    resolver = resolver or dns.resolver.Resolver()
    resolver.lifetime = 5
    out: dict = {"domain": domain}

    try:
        mx = sorted((a.preference, a.exchange.to_text().rstrip(".")) for a in resolver.resolve(domain, "MX"))
    except (dns.exception.DNSException, OSError):
        mx = []
    null_mx = mx == [(0, "")]
    out["mx"] = {"status": "ok" if mx and not null_mx else "warn", "hosts": [h for _, h in mx if h],
                 "notes": ["Null MX: the domain accepts no mail"] if null_mx else ([] if mx else ["No MX records"])}

    spf = [t for t in _txt(resolver, domain) if t.lower().startswith("v=spf1")]
    notes, status = [], "ok"
    if not spf:
        status, notes = "bad", ["No SPF record: anyone can send mail as this domain"]
    elif len(spf) > 1:
        status, notes = "bad", ["More than one SPF record (invalid, receivers treat it as none)"]
    else:
        terms = spf[0].split()[1:]
        lookups = sum(1 for t in terms if SPF_LOOKUPS.match(t))
        last = terms[-1].lower() if terms else ""
        if lookups > 10:
            status = "bad"
            notes.append(f"{lookups} DNS-lookup terms at the top level (limit 10)")
        if last in ("+all", "all"):
            status = "bad"
            notes.append("Ends in +all: allows every sender")
        elif last == "?all":
            status = "warn" if status == "ok" else status
            notes.append("Ends in ?all (neutral): spoofed mail is not rejected")
        elif last == "~all":
            notes.append("Ends in ~all (soft fail)")
        elif last == "-all":
            notes.append("Ends in -all (hard fail)")
    out["spf"] = {"status": status, "record": spf[0] if spf else "", "notes": notes}

    dmarc = [t for t in _txt(resolver, f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
    notes, status = [], "ok"
    if not dmarc:
        status, notes = "bad", ["No DMARC record"]
    else:
        tags = _tags(dmarc[0])
        policy = tags.get("p", "").lower()
        if policy == "none":
            status = "warn"
            notes.append("Policy none: reports only, spoofed mail is still delivered")
        elif policy in ("quarantine", "reject"):
            notes.append(f"Policy {policy}")
        else:
            status = "bad"
            notes.append("Missing or invalid p= policy")
        if tags.get("pct", "100") != "100":
            status = "warn" if status == "ok" else status
            notes.append(f"Applies to {tags['pct']}% of mail")
        if not tags.get("rua"):
            notes.append("No aggregate reports (rua) requested")
    out["dmarc"] = {"status": status, "record": dmarc[0] if dmarc else "", "notes": notes}

    sts = [t for t in _txt(resolver, f"_mta-sts.{domain}") if t.lower().startswith("v=stsv1")]
    out["mta_sts"] = {"status": "ok" if sts else "warn", "record": sts[0] if sts else "",
                      "notes": [] if sts else ["No MTA-STS: TLS for incoming mail is not enforced"]}

    try:
        signed = bool(resolver.resolve(domain, "DS"))
    except (dns.exception.DNSException, OSError):
        signed = False
    out["dnssec"] = {"status": "ok" if signed else "warn", "record": "",
                     "notes": ["Signed (DS record at the parent)"] if signed else ["Not signed"]}
    order = {"ok": 0, "warn": 1, "bad": 2}
    out["score"] = sum(2 - order[out[k]["status"]] for k in ("mx", "spf", "dmarc", "mta_sts", "dnssec"))
    return out
