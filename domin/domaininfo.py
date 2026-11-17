"""Domain info card (Posture · Analysis, one domain in the filter): registration data (RDAP), the owner and the
registrar's abuse contact, and the domain's security.txt (RFC 9116).

Look-ups go out on the inventory route (Settings · Routes) through the same client and public-address guard as an
inventory scan; internal zones never leave the LAN, so they get no look-ups at all. One result per domain is kept in
the kv table for a day; Refresh fetches again. RDAP and security.txt text is third-party input: the template escapes
it and links only http(s) URLs."""
from __future__ import annotations

import json
import re
import sqlite3
import time
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from datetime import UTC, datetime

import httpx

from domin import admin, proxy, tools

TTL = 24 * 3600            # seconds a stored result is shown before it is fetched again
MIN_REFRESH = 60           # seconds: Refresh on a result younger than this shows the stored one (no fetch loop)
TIMEOUT = 10.0             # seconds per security.txt request, the whole transfer included
MAX_TEXT = 64 * 1024       # bytes; RFC 9116 files are a few lines
KEY = "domaininfo:"
PATHS = ("/.well-known/security.txt", "/security.txt")
FIELDS = ("Contact", "Expires", "Policy", "Encryption", "Acknowledgments", "Preferred-Languages", "Canonical",
          "Hiring")
SINGLE = {"Expires", "Preferred-Languages"}   # RFC 9116: at most once; the first counts
EXPIRY_WARN_DAYS = 30
REDACTED = re.compile(r"redact|privacy|private|protected|withheld|not disclosed|gdpr", re.I)


# ---- security.txt ----

def parse_security_txt(text: str) -> dict:
    """Fields of a security.txt (RFC 9116): {field: [values]} for the known fields (case-insensitive names, comments
    and unknown fields skipped), signed (an OpenPGP cleartext signature wraps it; not verified), expires_ts (epoch
    seconds, None when absent or not a date) and valid (at least one Contact)."""
    signed = text.lstrip().startswith("-----BEGIN PGP SIGNED MESSAGE-----")
    lines = text.splitlines()
    if signed:
        start = next((i for i, ln in enumerate(lines) if not ln.strip()), len(lines))   # past the Hash: headers
        body = []
        for ln in lines[start + 1:]:
            if ln.startswith("-----BEGIN PGP SIGNATURE-----"):
                break
            body.append(ln[2:] if ln.startswith("- ") else ln)   # dash-escaped lines (RFC 4880 7.1)
        lines = body
    names = {f.lower(): f for f in FIELDS}
    fields: dict[str, list[str]] = {}
    for ln in lines:
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        key, sep, value = ln.partition(":")
        name, value = names.get(key.strip().lower()), value.strip()
        if not sep or not name or not value or (name in SINGLE and name in fields):
            continue
        fields.setdefault(name, []).append(value[:500])
    expires = (fields.get("Expires") or [""])[0]
    return {"fields": {f: fields[f] for f in FIELDS if f in fields}, "signed": signed,
            "expires_ts": _when(expires), "valid": bool(fields.get("Contact"))}


def _when(value: str) -> float | None:
    """Epoch seconds of an RFC 3339 date-time (Z or an offset), None when it isn't one."""
    try:
        t = datetime.fromisoformat(value.strip().replace("Z", "+00:00").replace("z", "+00:00"))
    except ValueError:
        return None
    return (t if t.tzinfo else t.replace(tzinfo=UTC)).timestamp()


def _get_text(client: httpx.Client, url: str) -> tuple[str, str]:
    """(final URL, text) of a text/plain answer; raises ValueError with a short reason for anything else."""
    deadline = time.monotonic() + TIMEOUT
    with client.stream("GET", url, timeout=TIMEOUT, headers={"Accept": "text/plain"}) as r:
        if r.status_code != 200:
            raise ValueError(f"HTTP {r.status_code}")
        kind = r.headers.get("content-type", "").split(";")[0].strip().lower()
        if kind != "text/plain":
            raise ValueError(f"not text/plain ({kind[:40] or 'no type'})")
        body = bytearray()
        for chunk in r.iter_bytes():
            body += chunk
            if len(body) > MAX_TEXT:
                raise ValueError("larger than 64 KB")
            if time.monotonic() > deadline:
                raise ValueError("too slow")
        return str(r.url), body.decode(r.charset_encoding or "utf-8", "replace")


def fetch_security_txt(domain: str, client: httpx.Client) -> dict:
    """The domain's security.txt: /.well-known/ first, then the top level. found=False with the first reason when
    neither holds a valid file."""
    reasons = []
    for path in PATHS:
        url = f"https://{domain}{path}"
        try:
            final, text = _get_text(client, url)
        except ValueError as exc:
            reasons.append(f"{path}: {exc}")
            continue
        except httpx.HTTPError as exc:
            reasons.append(f"{path}: {type(exc).__name__}")
            continue
        got = parse_security_txt(text)
        if got["valid"]:
            return {"found": True, "url": final, **got}
        reasons.append(f"{path}: no Contact field")
    return {"found": False, "error": "; ".join(reasons)}


# ---- registration (RDAP) ----

def registration(r: dict) -> dict:
    """The card's view of tools.rdap(): registrar, dates, status, name servers, DNSSEC, the registrant (or
    'redacted'), its country and the registrar's abuse contact."""
    if not r.get("found"):
        return {"found": False}
    ents = r.get("entities") or []
    role = lambda name: next((e for e in ents if name in e.get("roles", [])), {})  # noqa: E731
    registrar, registrant, abuse = role("registrar"), role("registrant"), role("abuse")
    owner = registrant.get("org") or registrant.get("name") or ""
    hidden = not owner or bool(REDACTED.search(owner)) or any(
        "registrant" in x.lower() and ("name" in x.lower() or "org" in x.lower()) for x in r.get("redacted") or [])
    country = registrant.get("country", "")
    return {"found": True, "registrar": registrar.get("name", ""), "created": r.get("registered", ""),
            "expires": r.get("expires", ""), "status": r.get("status", []), "nameservers": r.get("nameservers", []),
            "dnssec": r.get("dnssec", False), "owner": "" if hidden else owner,
            "country": "" if REDACTED.search(country) else country,
            "abuse_email": (registrar.get("abuse") or {}).get("email") or abuse.get("email", ""),
            "abuse_tel": (registrar.get("abuse") or {}).get("tel") or abuse.get("tel", ""),
            "source": r.get("source", "")}


# ---- fetch, cache, view ----

@contextmanager
def inventory_client(connect: Callable[[], AbstractContextManager[sqlite3.Connection]],
                     default: httpx.Client) -> Iterator[httpx.Client]:
    """The client an inventory scan uses: the default (direct) one, or one through the inventory route's hop after
    its handshake (fail closed: ProxyError when the route can't carry it)."""
    with connect() as conn:
        via = proxy.hop(conn, proxy.pick(proxy.get(conn), "", "inventory"), client=default)
    if not via:
        yield default
        return
    proxy.handshake(via)
    with tools.http_client(proxy=proxy.http_proxy(via)) as routed:
        yield routed


def fetch(domain: str, open_client: Callable[[], AbstractContextManager[httpx.Client]],
          now: float | None = None) -> dict:
    """Both look-ups for one domain (RDAP through tools.rdap, as the Tools page). ok=False when a look-up failed for
    a network reason (not stored)."""
    out = {"domain": domain, "at": now or time.time(), "ok": True, "rdap": {"found": False}, "rdap_error": "",
           "sectxt": {"found": False, "error": ""}}
    try:
        with open_client() as client:
            try:
                out["rdap"] = registration(tools.rdap(domain, client))
            except (httpx.HTTPError, ValueError, AttributeError, TypeError) as exc:   # a body that isn't RDAP JSON
                out["ok"], out["rdap_error"] = False, f"RDAP look-up failed: {type(exc).__name__}"
            out["sectxt"] = fetch_security_txt(domain, client)
    except proxy.ProxyError as exc:
        out["ok"], out["rdap_error"] = False, f"Inventory route unavailable: {exc}"
        out["sectxt"] = {"found": False, "error": "not fetched (inventory route unavailable)"}
    return out


def get(connect: Callable[[], AbstractContextManager[sqlite3.Connection]], domain: str,
        open_client: Callable[[], AbstractContextManager[httpx.Client]], refresh: bool = False,
        now: float | None = None) -> dict:
    """The stored result when younger than a day (Refresh: younger than a minute), else a fresh one, stored when
    both look-ups got an answer. No database connection is held during the look-ups."""
    now = now or time.time()
    with connect() as c:
        raw = admin.kv_get(c, KEY + domain)
    hit = json.loads(raw) if raw else None
    if hit and now - hit["at"] < (MIN_REFRESH if refresh else TTL):
        return {**hit, "cached": True}
    data = fetch(domain, open_client, now)
    if data["ok"]:
        with connect() as c:
            admin.kv_set(c, KEY + domain, json.dumps(data))
    return {**data, "cached": False}


def view(data: dict, now: float | None = None) -> dict:
    """Date flags for the card, worked out when shown: expires_days (registration), sectxt_expired."""
    now = now or time.time()
    reg, sec = dict(data.get("rdap") or {}), dict(data.get("sectxt") or {})
    when = _when(reg.get("expires", "")) if reg.get("expires") else None
    reg["expires_days"] = None if when is None else int((when - now) // 86400)
    reg["expires_soon"] = reg["expires_days"] is not None and reg["expires_days"] < EXPIRY_WARN_DAYS
    ts = sec.get("expires_ts")
    sec["expired"] = ts is not None and ts < now
    sec["expires"] = datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%d %H:%M UTC") if ts else ""
    fetched = datetime.fromtimestamp(data.get("at") or now).strftime("%Y-%m-%d %H:%M")
    return {**data, "rdap": reg, "sectxt": sec, "fetched": fetched}
