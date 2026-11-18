"""Domain info card (Posture · Analysis, one domain in the filter): registration data (RDAP, else WHOIS for TLDs
without an RDAP server), the owner and the registrar's abuse contact, and the domain's security.txt (RFC 9116).

Look-ups go out on the inventory route (Settings · Routes) through the same client and public-address guard as an
inventory scan; WHOIS (TCP 43) on the WHOIS route there (Direct, or a SOCKS5/HTTP CONNECT hop that resolves the
server's name; an unavailable route fails, never falls back to direct). An internal zone gets the public
registration look-up only (a split domain is also registered publicly); its security.txt is not fetched, since
internal DNS would send that to internal hosts. Special-use names (home.arpa, .local, .internal, ...) get no
look-ups at all. One result per domain is kept in the kv table for a day; Refresh fetches again. RDAP, WHOIS and
security.txt text is third-party input: the template escapes it and links only http(s) URLs."""
from __future__ import annotations

import base64
import ipaddress
import json
import re
import socket
import sqlite3
import time
import urllib.parse
import urllib.request
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
REG_BUDGET = 20.0          # seconds for the whole registration stage (RDAP, bootstrap, WHOIS); security.txt adds 10
WHOIS_PORT = 43
IANA_WHOIS = "whois.iana.org"
BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
BOOTSTRAP_TTL = 7 * 24 * 3600
SPECIAL_USE = {"arpa", "local", "localhost", "internal", "test", "example", "invalid", "onion", "lan", "home", "corp",
               "intranet", "private", "localdomain"}   # RFC 6761/6762/8375 and names ICANN keeps out of the root
_cache: dict[str, tuple[float, object]] = {}   # bootstrap TLD set and WHOIS servers per TLD (per process)


def special_use(domain: str) -> bool:
    """A name no public registry holds (home.arpa, .local, .internal, ...): no registration look-up."""
    return domain.rstrip(".").rsplit(".", 1)[-1].lower() in SPECIAL_USE


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
            if isinstance(exc, httpx.TransportError):
                break   # host or route unreachable: the fallback would wait out the same timeout
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
            "modified": r.get("changed", ""), "via": "RDAP", "source": r.get("source", "")}


# ---- registration (WHOIS, for TLDs without an RDAP server) ----

class WhoisError(Exception):
    """kind 'blocked': no connection (refused, unreachable, the proxy said no); 'timeout': connected, no answer."""

    def __init__(self, kind: str, detail: str = ""):
        super().__init__(f"{kind}: {detail}" if detail else kind)
        self.kind = kind


WHOIS_KEYS = {
    "registrar": ("registrar", "registrar name", "sponsoring registrar"),
    "created": ("created", "creation date", "registered", "registered on", "registration time",
                "domain record activated"),
    "expires": ("expires", "expire", "expiry date", "registry expiry date", "expiration date", "paid-till",
                "registrar registration expiration date"),
    "modified": ("modified", "updated date", "last updated", "last modified", "changed", "last-update"),
    "status": ("status", "domain status"),
    "nameservers": ("nserver", "name server", "nameserver", "nameservers"),
    "dnssec": ("dnssec",),
    "owner": ("holder", "registrant", "registrant name", "registrant organization", "registrant organisation"),
    "country": ("registrant country",),
    "abuse_email": ("registrar abuse contact email",),
    "abuse_tel": ("registrar abuse contact phone",),
}
_WHOIS_ALIAS = {alias: field for field, aliases in WHOIS_KEYS.items() for alias in aliases}


def parse_whois(text: str, server: str) -> dict:
    """The card's view of a WHOIS answer (the same keys as registration()); found=False when it holds no domain
    record (not registered). Comment lines (#, %) and unknown keys are skipped."""
    got: dict[str, list[str]] = {}
    for ln in text.splitlines():
        if ln.lstrip().startswith(("#", "%", ">>>")):
            continue
        key, sep, value = ln.partition(":")
        field, value = _WHOIS_ALIAS.get(key.strip().lower()), value.strip()
        if sep and field and value:
            got.setdefault(field, []).append(value[:200])
    if not any(got.get(f) for f in ("created", "expires", "nameservers", "registrar")):
        return {"found": False, "via": "WHOIS", "source": f"whois://{server}"}

    def first(f: str) -> str:
        return (got.get(f) or [""])[0]

    def day(v: str) -> str:
        return v[:10] if re.match(r"\d{4}-\d\d-\d\d", v) else v
    owner, dnssec = first("owner"), first("dnssec").lower()
    return {"found": True, "registrar": first("registrar"), "created": day(first("created")),
            "expires": day(first("expires")), "modified": day(first("modified")),
            "status": list(dict.fromkeys(v.split()[0] for v in got.get("status", []))),
            "nameservers": sorted({v.split()[0].lower().rstrip(".") for v in got.get("nameservers", [])}),
            "dnssec": ("signed" in dnssec and "unsigned" not in dnssec) or dnssec == "yes",
            "owner": "" if REDACTED.search(owner) else owner,
            "country": "" if REDACTED.search(first("country")) else first("country"),
            "abuse_email": first("abuse_email"), "abuse_tel": first("abuse_tel"), "via": "WHOIS",
            "source": f"whois://{server}"}


def route_hop(client: httpx.Client) -> dict | None:
    """The proxy a WHOIS connection takes: the inventory route's hop (inventory_client sets it), else the
    environment's HTTPS proxy when the client honours the environment, else None (direct)."""
    return getattr(client, "domin_hop", None) or env_hop(client)


def env_hop(client: httpx.Client) -> dict | None:
    """The environment's HTTPS proxy as a hop when the client honours the environment, else None (direct)."""
    if not getattr(client, "trust_env", False):
        return None
    env = urllib.request.getproxies()
    url = env.get("https") or env.get("http")
    if not url:
        return None
    u = urllib.parse.urlsplit(url if "://" in url else "http://" + url)
    kind = {"http": "http", "socks5": "socks5", "socks5h": "socks5"}.get(u.scheme)
    if not kind or not u.hostname:
        return None
    return {"type": kind, "host": u.hostname, "port": u.port or (1080 if kind == "socks5" else 80),
            "username": urllib.parse.unquote(u.username or ""), "password": urllib.parse.unquote(u.password or "")}


def _tunnel(s: socket.socket, hop: dict, host: str, port: int) -> None:
    """Open a TCP tunnel to host:port through the hop (HTTP CONNECT or SOCKS5; the hop resolves the name)."""
    user, pw = (hop.get("username") or "").encode(), (hop.get("password") or "").encode()
    if hop["type"] == "http":
        req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
        if user:
            req += "Proxy-Authorization: Basic " + base64.b64encode(user + b":" + pw).decode() + "\r\n"
        s.sendall((req + "\r\n").encode())
        head = b""
        while b"\r\n\r\n" not in head and len(head) < 8192:
            chunk = s.recv(1024)
            if not chunk:
                break
            head += chunk
        status = head.split(b"\r\n", 1)[0].decode("latin-1")
        if status.split()[1:2] != ["200"]:
            raise WhoisError("blocked", f"the proxy answered {status[:60] or 'nothing'}")
        return
    if hop["type"] != "socks5":
        raise WhoisError("blocked", f"a {hop['type']} proxy can't carry WHOIS")
    s.sendall(b"\x05\x02\x00\x02" if user else b"\x05\x01\x00")
    _, method = proxy._recv(s, 2)
    if method == 2:
        s.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(pw)]) + pw)
        if proxy._recv(s, 2)[1] != 0:
            raise WhoisError("blocked", "the proxy refused the user name or password")
    elif method != 0:
        raise WhoisError("blocked", "the proxy accepts none of the offered methods")
    name = host.encode()
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + port.to_bytes(2, "big"))
    reply = proxy._recv(s, 4)
    if reply[1] != 0:
        raise WhoisError("blocked", f"the proxy refused the connection (SOCKS reply {reply[1]})")
    proxy._recv(s, {1: 4, 4: 16}.get(reply[3], 0) or proxy._recv(s, 1)[0])
    proxy._recv(s, 2)


def _connect(host: str, port: int, hop: dict | None, timeout: float) -> socket.socket:
    """A TCP connection to a public host:port, direct or through the hop. WhoisError('blocked') when it can't be
    made."""
    try:
        if not hop:
            infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
            if any(not ipaddress.ip_address(str(i[4][0]).split("%")[0]).is_global for i in infos):
                raise WhoisError("blocked", f"{host} is not a public address")
            return socket.create_connection((host, port), timeout=timeout)
        addr = hop["host"]
        if addr.lower().endswith(proxy.MULLVAD_SUFFIX):   # relay names: public DNS, else Mullvad's in-tunnel one
            addr = proxy.resolve(addr)
        s = socket.create_connection((addr, int(hop["port"])), timeout=timeout)
    except OSError as exc:
        raise WhoisError("blocked", f"{type(exc).__name__}") from None
    except proxy.ProxyError as exc:   # a Mullvad relay name only its in-tunnel resolver knows, and it didn't
        raise WhoisError("blocked", str(exc)) from None
    try:
        _tunnel(s, hop, host, port)
    except (OSError, proxy.ProxyError, WhoisError) as exc:
        s.close()
        if isinstance(exc, WhoisError):
            raise
        raise WhoisError("blocked", f"proxy: {type(exc).__name__}") from None
    return s


def whois_query(server: str, query: str, hop: dict | None, deadline: float) -> str:
    """One WHOIS query (RFC 3912) to server:43: the answer as text, capped at MAX_TEXT, within TIMEOUT seconds and
    the stage deadline (time.monotonic)."""
    deadline = min(deadline, time.monotonic() + TIMEOUT)
    left = deadline - time.monotonic()
    if left < 1:
        raise WhoisError("timeout", "no time left")
    body = bytearray()
    with _connect(server, WHOIS_PORT, hop, left) as s:
        try:
            s.sendall(query.encode("ascii", "replace") + b"\r\n")
            while len(body) < MAX_TEXT:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise WhoisError("timeout", f"{server} answered too slowly")
                s.settimeout(left)
                chunk = s.recv(4096)
                if not chunk:
                    break
                body += chunk
        except TimeoutError:
            raise WhoisError("timeout", f"{server} did not answer in time") from None
        except OSError as exc:
            raise WhoisError("blocked", f"{type(exc).__name__}") from None
    return bytes(body[:MAX_TEXT]).decode("utf-8", "replace")


def _cached(key: str, ttl: float, make: Callable[[], object]) -> object:
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < ttl:
        return hit[1]
    value = make()
    _cache[key] = (time.time(), value)
    return value


def whois_server(tld: str, hop: dict | None, deadline: float) -> str:
    """The TLD's WHOIS server as IANA lists it ('' when it has none); kept for a week per process."""
    def ask() -> str:
        text = whois_query(IANA_WHOIS, tld, hop, deadline)
        return next((ln.split(":", 1)[1].strip().lower() for ln in text.splitlines()
                     if ln.lower().startswith("whois:") and ln.split(":", 1)[1].strip()), "")
    return str(_cached("whois:" + tld, BOOTSTRAP_TTL, ask))


def has_rdap(tld: str, client: httpx.Client, deadline: float) -> bool | None:
    """Whether the IANA RDAP bootstrap (dns.json) lists the TLD; None when the bootstrap can't be read."""
    left = min(TIMEOUT, deadline - time.monotonic())
    if left < 1 and "rdap-bootstrap" not in _cache:
        return None

    def load() -> frozenset[str]:
        got = tools.get_json(client, BOOTSTRAP, timeout=max(1.0, left))
        if got is None or not isinstance(got[1], dict):
            raise ValueError("no bootstrap")
        return frozenset(t.lower() for s in got[1].get("services") or [] for t in s[0])
    try:
        return tld in _cached("rdap-bootstrap", BOOTSTRAP_TTL, load)   # type: ignore[operator]
    except (httpx.HTTPError, ValueError, TypeError, KeyError, IndexError):
        return None


WhoisHop = Callable[[], "dict | None"]   # the WHOIS route's hop (None = direct); raises proxy.ProxyError


def lookup_registration(domain: str, client: httpx.Client, deadline: float,
                        whois: WhoisHop | None = None) -> tuple[dict, str]:
    """(card view, error) of the domain's registration: RDAP; for a TLD the RDAP bootstrap doesn't list (or when it
    can't be read), WHOIS at the TLD's IANA-listed server. whois: the WHOIS route (Settings · Routes), resolved only
    when WHOIS is needed; Direct still honours the environment's proxy. Without it WHOIS takes the client's route.
    error is set for a network failure or an unavailable WHOIS route (the result is then not stored)."""
    try:
        reg = registration(tools.rdap(domain, client))
    except (httpx.HTTPError, ValueError, AttributeError, TypeError) as exc:   # a body that isn't RDAP JSON
        return {"found": False}, f"RDAP look-up failed: {type(exc).__name__}"
    tld = domain.rstrip(".").rsplit(".", 1)[-1].lower()
    if reg["found"] or has_rdap(tld, client, deadline):
        return reg, ""
    if whois is None:
        hop = route_hop(client)
    else:
        try:
            hop = whois() or env_hop(client)
        except proxy.ProxyError as exc:
            return {"found": False}, str(exc)
    try:
        server = whois_server(tld, hop, deadline)
        if not server:
            return {"found": False, "note": f"No RDAP or WHOIS server for .{tld}"}, ""
        return parse_whois(whois_query(server, domain, hop, deadline), server), ""
    except WhoisError as exc:
        what = "WHOIS blocked" if exc.kind == "blocked" else "WHOIS timed out"
        return {"found": False}, f"registration data unavailable (no RDAP; {what})"


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
        routed.domin_hop = via   # type: ignore[attr-defined]  (route_hop: WHOIS takes the same hop)
        yield routed


INTERNAL_SECTXT = {"found": False, "error": "not checked (internal zone)"}


def whois_route(connect: Callable[[], AbstractContextManager[sqlite3.Connection]],
                client: httpx.Client | None = None) -> WhoisHop:
    """The WHOIS route's hop, looked up when called (lookup_registration's whois)."""
    def resolve() -> dict | None:
        with connect() as conn:
            return proxy.whois_hop(conn, client)
    return resolve


def fetch(domain: str, open_client: Callable[[], AbstractContextManager[httpx.Client]],
          now: float | None = None, internal: bool = False, whois: WhoisHop | None = None) -> dict:
    """The look-ups for one domain (RDAP through tools.rdap as the Tools page, else WHOIS; security.txt unless the
    domain is an internal zone). ok=False when a look-up failed for a network reason (not stored). Worst case:
    REG_BUDGET for the registration stage plus TIMEOUT for security.txt."""
    out = {"domain": domain, "at": now or time.time(), "ok": True, "internal": internal, "rdap": {"found": False},
           "rdap_error": "", "sectxt": dict(INTERNAL_SECTXT) if internal else {"found": False, "error": ""}}
    deadline = time.monotonic() + REG_BUDGET
    try:
        with open_client() as client:
            out["rdap"], err = lookup_registration(domain, client, deadline, whois)
            if err:
                out["ok"], out["rdap_error"] = False, err
            if not internal:
                out["sectxt"] = fetch_security_txt(domain, client)
    except proxy.ProxyError as exc:
        out["ok"], out["rdap_error"] = False, f"Inventory route unavailable: {exc}"
        if not internal:
            out["sectxt"] = {"found": False, "error": "not fetched (inventory route unavailable)"}
    return out


def get(connect: Callable[[], AbstractContextManager[sqlite3.Connection]], domain: str,
        open_client: Callable[[], AbstractContextManager[httpx.Client]], refresh: bool = False,
        now: float | None = None, internal: bool = False, whois: WhoisHop | None = None) -> dict:
    """The stored result when younger than a day (Refresh: younger than a minute), else a fresh one, stored when
    every look-up got an answer. No database connection is held during the look-ups. internal: an internal zone
    (registration only; stored under its own key). whois: the WHOIS route (whois_route)."""
    now = now or time.time()
    key = KEY + domain + ("#internal" if internal else "")
    with connect() as c:
        raw = admin.kv_get(c, key)
    hit = json.loads(raw) if raw else None
    if hit and now - hit["at"] < (MIN_REFRESH if refresh else TTL):
        return {**hit, "cached": True}
    data = fetch(domain, open_client, now, internal, whois)
    if data["ok"]:
        with connect() as c:
            admin.kv_set(c, key, json.dumps(data))
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
