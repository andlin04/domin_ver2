"""Web app: server-rendered pages (Jinja2) with chart data as JSON blocks, plus a small JSON API.

Run: uvicorn --factory domin.web:create_app --port 8002 (behind nginx; X-Real-IP is trusted from localhost only)."""
from __future__ import annotations

import csv
import gzip
import hmac
import io
import ipaddress
import json
import logging
import secrets
import threading
import time
from collections import defaultdict, deque
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Annotated
from urllib.parse import parse_qs, quote, urlencode, urlsplit

import httpx
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi import Path as PathParam
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from markupsafe import Markup
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import (
    access,
    admin,
    csvimport,
    cve,
    db,
    discovery,
    fingerprint,
    jobs,
    mullvad,
    netscope,
    posture,
    proxy,
    reports,
    schedules,
    tags,
    tools,
    totp,
    users,
)
from .config import Settings
from .validate import is_internal, normalize_domain

HERE = Path(__file__).parent
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
SECURITY_HEADERS = {"Content-Security-Policy": CSP, "X-Content-Type-Options": "nosniff",
                    "Referrer-Policy": "same-origin", "X-Frame-Options": "DENY",
                    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
                    "Cross-Origin-Opener-Policy": "same-origin", "Cross-Origin-Resource-Policy": "same-origin"}
HEAVY_AT_ONCE = 2   # filtered searches and CSV downloads (seconds of database work each) running in parallel
CHURN_SCANS = 40  # host churn chart: the newest N scans of a domain
MAX_ID = 2**63 - 1   # SQLite INTEGER; larger ids would raise OverflowError (500)
SEARCH_PAGE = 100   # search results per page
DRILL_FORMAT = 2   # layout of /data/drill.json; raise it when the columns change (2: EU column)
SEARCH_CSV_MAX = 100_000   # rows in a search download
SEARCH_LABELS = {"host": "Host name", "ip": "Address", "asn": "ASN", "prefix": "Prefix", "netname": "Network",
                 "descr": "Description", "country": "Country"}
PathId = Annotated[int, PathParam(ge=0, le=MAX_ID)]
QueryId = Annotated[int, Query(ge=0, le=MAX_ID)]
ADMIN = "/admin"   # shown and served only to DOMIN_ADMIN_IPS
COOKIE = "__Host-domin_admin"   # __Host-: Secure, path /, no Domain; the site must be served over HTTPS
log = logging.getLogger("domin.web")


class ScanIn(BaseModel):
    domain: str


def csv_safe(value):
    """Spreadsheets run cells that start with = + - @ as formulas; RDAP text is third-party input."""
    return "'" + value if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r") else value


def session_for(c, request: Request, settings: Settings) -> dict | None:
    """The request's session; with sign-in turned off (DOMIN_ALLOW_NO_LOGIN + Settings) the stand-in one, which counts
    in the admin area always and in the inventory and posture areas unless Settings requires sign-in there."""
    s = admin.session(c, request.cookies.get(COOKIE))
    if s or not settings.allow_no_login or not getattr(request.state, "no_login_peer", False):
        return s   # the stand-in only for DOMIN_ADMIN_IPS (set per request by the middleware)
    where = access.area(request.url.path)
    if where != "admin" and users.signin_required(c)[where]:
        return None
    return admin.no_login_session(c)


def safe_next(target: str | None) -> str:
    """A same-site path to return to after sign-in ('' = none): starts with one /, no backslash or control text."""
    t = (target or "").strip()
    if not t.startswith("/") or t.startswith("//") or "\\" in t or any(ord(ch) < 32 for ch in t) or len(t) > 2000:
        return ""
    return t


def create_app(settings: Settings | None = None, http: httpx.Client | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    if settings.allow_no_login:   # dev/lab only: refused without a private admin allowlist; loud when active
        if why := settings.no_login_refusal():
            log.error("DOMIN_ALLOW_NO_LOGIN refused (%s): sign-in stays on", why)
            settings = replace(settings, allow_no_login=False)
        else:
            log.warning("DOMIN_ALLOW_NO_LOGIN is active: sign-in can be turned off for DOMIN_ADMIN_IPS (%d "
                        "network(s)); never on a production install", len(settings.admin_ips))
    db.init(settings.db_path)
    app = FastAPI(title="domin", docs_url=None, redoc_url=None, openapi_url=None)
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    templates = Jinja2Templates(directory=HERE / "templates")
    templates.env.globals["eu_status"] = db.eu_status
    client = http or tools.http_client()
    lookups: dict[str, deque[float]] = defaultdict(deque)

    def conn():
        return db.connect(settings.db_path)

    admin_nets = [ipaddress.ip_network(x, strict=False) for x in settings.admin_ips]
    internal_nets = [ipaddress.ip_network(x, strict=False) for x in settings.internal_ips]

    def peer_ip(request: Request) -> str:
        """The visitor's address: X-Real-IP only when nginx on this host proxies (nginx sets it from $remote_addr,
        which with --cloudflare is CF-Connecting-IP from Cloudflare's ranges only); other headers are never read."""
        peer = request.client.host if request.client else ""
        if peer in ("127.0.0.1", "::1"):
            peer = request.headers.get("x-real-ip", peer).strip()
        return peer

    def client_ip(request: Request) -> str:
        """Peer address for rate limits and statistics; an IPv6 client counts as its /64."""
        peer = peer_ip(request)
        try:
            ip = ipaddress.ip_address(peer)
        except ValueError:
            return peer[:64]
        return str(ipaddress.ip_network(f"{ip}/64", strict=False)) if ip.version == 6 else str(ip)

    def peer_in(request: Request, nets) -> bool:
        try:
            ip = ipaddress.ip_address(peer_ip(request))
        except ValueError:
            return False
        return any(ip in n for n in nets)

    def net_ok(request: Request) -> bool:
        """Optional network allowlist in front of the whole signed-in area; open when DOMIN_ADMIN_IPS is empty, in
        which case the sign-in alone governs access."""
        return not admin_nets or peer_in(request, admin_nets)

    def live() -> Settings:
        with conn() as c:
            return admin.effective(settings, c)

    def limit_lookups(request: Request) -> None:
        """In-process sliding window for the live lookups (outbound RDAP/DNS on each call)."""
        now, who, per_minute = time.monotonic(), client_ip(request), live().lookups_per_minute
        q = lookups[who]
        while q and q[0] < now - 60:
            q.popleft()
        if len(q) >= per_minute:
            raise HTTPException(429, f"At most {per_minute} lookups per minute")
        q.append(now)
        if len(lookups) > 10000:   # bound memory: drop clients with no recent calls
            for k in [k for k, v in lookups.items() if not v or v[-1] < now - 60]:
                del lookups[k]

    def viewer(request: Request) -> tuple[dict | None, str]:
        """The signed-in user behind a public page request (and the session's CSRF token), or (None, "")."""
        if COOKIE not in request.cookies and not settings.allow_no_login:
            return None, ""
        with conn() as c:
            sess = session_for(c, request, settings)
            if sess and sess["user_id"]:
                u = users.get(c, sess["user_id"])
                if u and not u["disabled"]:
                    return u, sess["csrf"]
        return None, ""

    def scope_of(request: Request) -> access.Scope:
        """What this request may see (domin.access): a signed-in power user its grants; admins, sign-in off and
        anonymous visitors of the public inventory everything."""
        if not hasattr(request.state, "scope"):
            user, _ = viewer(request)
            with conn() as c:
                request.state.scope = access.for_user(c, user) if user else access.FULL
        return request.state.scope

    def page(request: Request, name: str, status: int = 200, **ctx) -> HTMLResponse:
        # Resolve the signed-in user for the nav on public pages too, so the menu keeps its admin links
        # everywhere a logged-in user goes (the admin views pass their own user and skip this lookup).
        user, csrf = ctx.pop("user", None), ""
        if user is None:
            user, csrf = viewer(request)
        admin_csrf = csrf if user and user["role"] == "admin" else ""   # admins can drop a domain from a public page
        grants = getattr(request.state, "scope", None) or (scope_of(request) if user else access.NONE)
        ctx = {"signed_in_hint": COOKIE in request.cookies, "net_ok": net_ok(request), "user": user, "csrf": csrf,
               "admin_base": ADMIN, "admin_csrf": admin_csrf, "access": grants, "role_labels": users.ROLE_LABELS,
               **ctx}
        return templates.TemplateResponse(request, name, ctx, status_code=status)

    def domain_or_404(c, name: str, scope: access.Scope) -> dict:
        """The domain, or 404: unknown and outside the request's grants answer the same."""
        d = db.domain(c, name)
        if not d or not scope.sees(d["name"]):
            raise HTTPException(404, f"{name} has not been scanned")
        return d

    def visit_kind(request: Request, status: int) -> tuple[str, str] | None:
        """(kind, domain) for the visit statistics; None = not counted (assets, polling, health, admin)."""
        path = request.url.path
        if request.method == "POST" and path == "/api/scan":
            return ("scan" if status == 200 else "limited" if status == 429 else None), ""
        if request.method != "GET" or status != 200:
            return None
        if path == ADMIN or path.startswith(ADMIN + "/"):
            return None
        parts = path.strip("/").split("/")
        if path == "/search.csv" or path.startswith("/scans/") and path.endswith(".csv"):
            return "download", ""
        if path.startswith(("/api/rdap/", "/api/email/")):
            return "tool", parts[-1]
        if path.startswith(("/api/", "/static/", "/healthz", "/data/")):
            return None
        return "page", parts[1] if parts[0] == "d" and len(parts) > 1 else ""

    def record_visit(request: Request, kind: str, domain: str, scan_domain: str | None) -> None:
        ref = urlsplit(request.headers.get("referer", "")).hostname or ""
        with conn() as c:
            admin.record(c, kind=kind, path=request.url.path, domain=scan_domain or domain, ip=client_ip(request),
                         agent=request.headers.get("user-agent", "")[:300],
                         ref="" if ref == request.url.hostname else ref)

    def signin_gate(request: Request) -> Response | None:
        """Settings, Sign-in: a visitor without a user on a page whose area requires sign-in goes to the sign-in page
        (API, drill data, CSV and form posts: 401). Inventory: every visitor without a session, except private API
        clients (DOMIN_INTERNAL_IPS) on /api/. Posture: only the lab stand-in is turned away here; a visitor without
        a session gets the posture handlers' own answer, as before.
        Then the feature rights (access.ROUTES) of a signed-in user: none = 404, read only on a write = 403."""
        path = request.url.path
        if path.startswith("/static/") or path == "/healthz":
            return None
        where = access.area(path)
        need = access.feature_of(request.method, path)
        if where == "inventory" and path.startswith("/api/") and peer_in(request, internal_nets):
            return None
        machine = request.method != "GET" or path.startswith(("/api/", "/data/")) or path.endswith(".csv")
        with conn() as c:
            required = where != "admin" and users.signin_required(c)[where]
            if not required and (not need or (COOKIE not in request.cookies and not settings.allow_no_login)):
                return None
            s = session_for(c, request, settings)
            u = users.get(c, s["user_id"]) if s and s["user_id"] else None
            u = u if u and not u["disabled"] else None
            if u is None:
                stand_in = (settings.allow_no_login and request.state.no_login_peer
                            and admin.no_login_session(c))
                if not required or (where == "posture" and not stand_in):
                    return None   # a public page, or the handler's own answer (the sign-in page)
                if machine:
                    return JSONResponse({"error": "Sign in first."}, status_code=401, headers=PRIVATE)
                here = path + (f"?{request.url.query}" if request.url.query else "")
                return RedirectResponse(f"{ADMIN}?{urlencode({'next': here})}", status_code=303, headers=PRIVATE)
            if not need:
                return None
            scope = access.for_user(c, u)
        feature, level = need
        if scope.can(feature, level):
            return None
        # Feature rights (access.FEATURES): no right at all answers as an unknown page, read without write as a
        # refused action, as the domain grants do.
        if not scope.can(feature):
            code, msg = 404, "Not Found"
        else:
            code, msg = 403, f"{access.feature_label(feature)}: your account may only read here."
        if path.startswith(("/api/", "/data/")) or path.endswith(".csv") or "json" in request.headers.get("accept", ""):
            return JSONResponse({"error": msg}, status_code=code, headers=PRIVATE)
        request.state.scope = scope
        resp = page(request, "error.html", code, message=msg, code=code)
        resp.headers.update(PRIVATE)
        return resp

    @app.middleware("http")
    async def headers(request: Request, call_next):
        path = request.url.path
        request.state.no_login_peer = settings.allow_no_login and peer_in(request, admin_nets)
        if (path == ADMIN or path.startswith(ADMIN + "/")) and not net_ok(request):
            resp = await run_in_threadpool(not_found, request)   # the same answer as a path that doesn't exist
        else:
            resp = await run_in_threadpool(signin_gate, request) or await call_next(request)
        resp.headers.update(SECURITY_HEADERS)
        if request.url.path.startswith("/static/"):
            resp.headers["Cache-Control"] = "no-cache"   # revalidate (ETag) so a deploy shows at once
        kind = visit_kind(request, resp.status_code)
        if kind and kind[0]:
            try:   # statistics never break a page
                await run_in_threadpool(record_visit, request, *kind, getattr(request.state, "domain", None))
            except Exception:
                log.exception("visit not recorded")
        return resp

    def not_found(request: Request) -> Response:
        """An unknown path, and a hidden one (the admin area from outside DOMIN_ADMIN_IPS), answer exactly alike:
        a browser page (HTML accepted, not /api/) gets the styled 404, everything else the framework's JSON."""
        if not request.url.path.startswith("/api/") and "text/html" in request.headers.get("accept", ""):
            return page(request, "error.html", 404, message="Not Found", code=404)
        return JSONResponse({"detail": "Not Found"}, status_code=404)

    @app.exception_handler(StarletteHTTPException)
    async def routing_error(request: Request, exc: StarletteHTTPException):
        """Errors raised by the router itself (no such path, wrong method): unknown paths via not_found."""
        if exc.status_code == 404:
            return not_found(request)
        return await http_exception_handler(request, exc)

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"error": exc.detail}, status_code=exc.status_code)
        return page(request, "error.html", exc.status_code, message=exc.detail, code=exc.status_code)

    @lru_cache(maxsize=32)
    def overview_data(version: str, scope: access.Scope) -> dict:
        with conn() as c:
            return {"totals": db.totals(c, scope), "per_day": db.scans_per_day(c, scope),
                    "countries": db.top_latest(c, "country", scope=scope),
                    "netnames": db.top_latest(c, "netname", scope=scope),
                    "asns": db.top_latest(c, "asn", scope=scope), "map": db.top_latest(c, "country", 400, scope),
                    "eu": db.eu_per_day(c, scope)}

    def data_version(c) -> str:
        return str(c.execute("SELECT COALESCE(MAX(id), 0) FROM scans").fetchone()[0])

    # --- pages ---------------------------------------------------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    def overview(request: Request):
        scope = scope_of(request)
        with conn() as c:
            version = data_version(c)
            domains = db.domains_overview(c, scope=scope)
            recent = jobs.recent(c, 8, scope)
            src = drill_src(c, False, scope)
        return page(request, "overview.html", data=overview_data(version, scope), domains=domains, recent=recent,
                    drill_rows=drill_preview(version, scope), fields=SEARCH_LABELS, drill_src=src)

    @lru_cache(maxsize=16)
    def drill_preview(version: str, scope: access.Scope) -> list[dict]:
        """The first records for the overview's Drilldown tab (latest scans, no filter)."""
        with conn() as c:
            return db.search(c, limit=SEARCH_PAGE, scope=scope)[0]

    @app.get("/d/{name}", response_class=HTMLResponse)
    def domain_page(request: Request, name: str, scan: QueryId | None = None):
        scope = scope_of(request)
        with conn() as c:
            d = domain_or_404(c, name, scope)
            hist = db.history(c, name)
            done = [h for h in hist if h["status"] == "done"]
            if not done:
                raise HTTPException(404, f"{name} has no finished scan yet")
            current = next((h for h in done if h["id"] == scan), done[-1])
            idx = done.index(current)
            previous = done[idx - 1] if idx else None
            rows = db.records(c, current["id"])
            prev_rows = db.records(c, previous["id"]) if previous else []
            churn = churn_series(c, done[-CHURN_SCANS:])
            open_job = c.execute("SELECT id FROM jobs WHERE domain = ? AND status IN ('queued', 'running')",
                                 (name,)).fetchone()
        change = db.diff(prev_rows, rows) if previous else None
        charts = {"history": done, "churn": churn, "current": current["id"],
                  "countries": db.breakdown(rows, "country", 8), "netnames": db.breakdown(rows, "netname", 10),
                  "asns": db.breakdown(rows, "asn", 10), "map": db.country_map(rows)}
        user, csrf = viewer(request)
        posture_rows, posture_trend, host_tags, suggested, tag_counts, net_tags = [], [], {}, {}, {}, {}
        tag = request.query_params.get("tag", "")
        # posture results, host tags and schedules are signed-in reports, each behind its feature right
        see_posture, see_tags, see_scans = (bool(user) and scope.can(f) for f in ("posture", "tags", "scans"))
        if see_posture:
            with conn() as c:
                posture_rows = posture.current(c, d["name"])
                posture_trend = posture.trend(c, d["name"])
        if see_tags:
            with conn() as c:
                host_tags = tags.for_hosts(c, sorted({r["host"] for r in rows}))
                rules = users.get_scope(c)["net_tags"]
            suggested = tags.suggestions(rows, posture_rows, host_tags)
            if rules:   # Settings > Network tags: shown beside the hand-set tags, not removable here
                ips: dict[str, list[str]] = {}
                for r in rows:
                    ips.setdefault(r["host"], []).append(r["ip"])
                net_tags = {h: t for h, a in ips.items() if (t := users.net_tags(rules, a))}
            for t in (t for ts in [*host_tags.values(), *net_tags.values()] for t in ts):
                tag_counts[t] = tag_counts.get(t, 0) + 1
            if tag in tag_counts:
                rows = [r for r in rows if tag in host_tags.get(r["host"], []) + net_tags.get(r["host"], [])]
            else:
                tag = ""
        posture_report = posture.report(posture_rows)
        posture_report["charts"]["trend"] = posture_trend
        sched_rows, sched_opts, discovered, internal, viewers = [], None, [], False, None
        if see_scans:   # schedules and the nmap discovery stage: signed-in, like posture
            with conn() as c:
                sched_rows = schedules.for_domain(c, d["name"])
                if scope.acts("scans", d["name"]):
                    sched_opts = schedule_opts(c, d["name"])
                if current.get("discovery"):
                    discovered = db.discovery_results(c, current["id"])
                internal = is_internal(d["name"], admin.effective(settings, c).internal_zones)
        if user and scope.manages(d["name"]):   # domain admins (and admins) grant viewer here
            with conn() as c:
                viewers = access.viewers_panel(c, d["name"], user)
        return page(request, "domain.html", domain=d, scans=done, current=current, previous=previous,
                    rows=rows, change=change, charts=charts, open_job=open_job["id"] if open_job else None,
                    user=user, csrf=csrf, admin_csrf=csrf if user and user["role"] == "admin" else "",
                    posture_report=posture_report, host_tags=host_tags, suggested=suggested, net_tags=net_tags,
                    tag_counts=dict(sorted(tag_counts.items())), tag=tag, sched_rows=sched_rows,
                    sched_opts=sched_opts, discovered=discovered, viewers=viewers,
                    domain_internal=internal, notice=NOTICES.get(request.query_params.get("ok", ""), ""))

    def churn_series(c, scans: list[dict]) -> list[dict]:
        """Host names added / removed at each scan versus the one before it."""
        if len(scans) < 2:
            return []
        ids = [s["id"] for s in scans]
        sets: dict[int, set[str]] = {i: set() for i in ids}
        q = f"SELECT scan_id, host FROM records WHERE scan_id IN ({','.join('?' * len(ids))})"
        for r in c.execute(q, ids):
            sets[r["scan_id"]].add(r["host"])
        out = [{"id": b["id"], "started": b["started"], "added": len(sets[b["id"]] - sets[a["id"]]),
                "removed": len(sets[a["id"]] - sets[b["id"]])} for a, b in zip(scans, scans[1:], strict=False)]
        return out if any(r["added"] or r["removed"] for r in out) else []   # an empty chart says nothing

    @app.get("/d/{name}/compare", response_class=HTMLResponse)
    def compare(request: Request, name: str, a: QueryId, b: QueryId):
        with conn() as c:
            d = domain_or_404(c, name, scope_of(request))
            sa, sb = db.scan(c, a), db.scan(c, b)
            if not sa or not sb or sa["domain"] != name or sb["domain"] != name:
                raise HTTPException(404, "scan not found for this domain")
            if sa["started"] > sb["started"]:
                sa, sb = sb, sa
            change = db.diff(db.records(c, sa["id"]), db.records(c, sb["id"]))
            scans = [h for h in db.history(c, name) if h["status"] == "done"]
        return page(request, "compare.html", domain=d, a=sa, b=sb, change=change, scans=scans)

    def search_args(request: Request, q: str, field: str, scope: str) -> dict:
        """The search, plus the column filters f_<column> (each one narrows the result further)."""
        cols = {k: request.query_params.get("f_" + k, "").strip()[:200] for k in ("domain", "eu", *db.SEARCH_FIELDS)}
        return {"q": q.strip()[:200], "field": field if field in db.SEARCH_FIELDS else "",
                "history": scope == "all", "columns": {k: v for k, v in cols.items() if v}}

    @lru_cache(maxsize=64)
    def summary(version: str, q: str, field: str, history: bool, cols: tuple,
                scope: access.Scope = access.FULL) -> dict:
        with conn() as c:
            return db.search_summary(c, q, field, history, dict(cols), scope=scope)

    @lru_cache(maxsize=16)
    def history_page(hour: str, offset: int) -> tuple[list[dict], int]:
        with conn() as c:
            return db.search(c, history=True, limit=SEARCH_PAGE, offset=offset)

    # The Drilldown filters in the browser: it fetches the whole dataset once (gzip'd JSON, cached by the browser
    # until the next scan, or the next hour for the history), so typing in a filter costs the server nothing.
    # The server-side search above stays as the fallback (no JavaScript, data not loaded) and for the CSV.
    drill_cache: dict[bool, tuple[str, bytes]] = {}
    drill_locks = {False: threading.Lock(), True: threading.Lock()}

    def drill_key(c, history: bool, scope: access.Scope = access.FULL) -> str:
        """Changes with the data (latest scan, or the hour), with DRILL_FORMAT, so browsers never reuse a cached copy
        in an older layout, and with a power user's grants."""
        key = f"{DRILL_FORMAT}-{db.now()[:13] if history else data_version(c)}"
        return key if scope.sees_all else f"{key}-{scope.key()}"

    def drill_data(key: str, history: bool) -> bytes:
        with drill_locks[history]:   # one build at a time; the others wait for it
            if drill_cache.get(history, ("",))[0] != key:
                with conn() as c:
                    data = db.drill_columns(c, history)
                drill_cache[history] = key, gzip.compress(json.dumps(data, separators=(",", ":")).encode(), 6)
            return drill_cache[history][1]

    def drill_src(c, history: bool, grants: access.Scope = access.FULL) -> str:
        return f"/data/drill.json?scope={'all' if history else 'latest'}&v={drill_key(c, history, grants)}"

    @app.get("/data/drill.json")
    def drill_json(request: Request, scope: str = "latest", v: str = ""):
        history, grants = scope == "all", scope_of(request)
        with conn() as c:
            key = drill_key(c, history, grants)
            if not grants.sees_all:   # a power user's domains: built per request, cached by that browser only
                data = db.drill_columns(c, history, grants)
                cache = "private, max-age=31536000, immutable" if v == key else "private, no-cache"
                return Response(gzip.compress(json.dumps(data, separators=(",", ":")).encode(), 6),
                                media_type="application/json",
                                headers={"Content-Encoding": "gzip", "Cache-Control": cache})
        cache = "public, max-age=31536000, immutable" if v == key else "no-cache"
        return Response(drill_data(key, history), media_type="application/json",
                        headers={"Content-Encoding": "gzip", "Cache-Control": cache})

    def warm_history() -> None:
        """The unfiltered whole history (1.5M records, 800k host and address pairs) takes ~15 s for the figures and
        ~5 s per page: both are keyed by the hour (not by the latest scan), and the figures, first page and the
        browser's datasets are computed here at start and early each hour, so the default view never waits."""
        while True:
            try:
                summary(db.now()[:13], "", "", True, ())
                history_page(db.now()[:13], 0)
                with conn() as c:
                    keys = drill_key(c, False), drill_key(c, True)
                drill_data(keys[0], False)
                drill_data(keys[1], True)
            except Exception:
                log.exception("history figures not computed")
            time.sleep(3600 - time.time() % 3600 + 5)

    threading.Thread(target=warm_history, daemon=True, name="warm-history").start()

    heavy_slots = threading.BoundedSemaphore(HEAVY_AT_ONCE)

    @contextmanager
    def heavy():
        """Many parallel filtered searches or downloads would starve the pages: wait briefly for a slot, else 503."""
        if not heavy_slots.acquire(timeout=10):
            raise HTTPException(503, "Busy with other searches; try again in a moment")
        try:
            yield
        finally:
            heavy_slots.release()

    @app.get("/all", response_class=HTMLResponse)
    @app.get("/search", response_class=HTMLResponse, include_in_schema=False)   # the page's first address
    def all_domains(request: Request, q: str = "", field: str = "", scope: str = "latest",
                    page_no: Annotated[int, Query(alias="page", ge=1, le=100_000)] = 1):
        args = search_args(request, q, field, scope)
        grants = scope_of(request)
        offset = (page_no - 1) * SEARCH_PAGE
        unfiltered_history = args["history"] and not args["q"] and not args["columns"] and grants.sees_all
        if unfiltered_history:   # computed hourly in the background (warm_history)
            with conn() as c:
                src = drill_src(c, True)
            rows, total = history_page(db.now()[:13], offset)
            stats = summary(db.now()[:13], "", "", True, ())
        else:
            with heavy(), conn() as c:
                version = data_version(c)
                src = drill_src(c, args["history"], grants)
                rows, total = db.search(c, **args, limit=SEARCH_PAGE, offset=offset, scope=grants)
                stats = summary(version, args["q"], args["field"], args["history"],
                                tuple(sorted(args["columns"].items())), grants)
        pages = max(1, -(-total // SEARCH_PAGE))
        return page(request, "search.html", rows=rows, total=total, page_no=page_no, pages=pages, stats=stats,
                    hourly=unfiltered_history,
                    q=args["q"], field=args["field"], scope="all" if args["history"] else "latest",
                    cols=args["columns"], fields=SEARCH_LABELS, drill_src=src)

    @app.get("/search.csv")
    def search_csv(request: Request, q: str = "", field: str = "", scope: str = "latest"):
        args = search_args(request, q, field, scope)
        grants = scope_of(request)
        with heavy(), conn() as c:
            rows, _ = db.search(c, **args, limit=SEARCH_CSV_MAX, scope=grants)
        names = ["domain", *db.RECORD_FIELDS, "eu", *(["first_seen", "last_seen", "seen"] if args["history"]
                                                 else ["last_seen"])]
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=names, extrasaction="ignore")
        w.writeheader()
        w.writerows({k: csv_safe(v) for k, v in r.items()} for r in rows)
        return Response(buf.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="domin_search_{db.now()[:10]}.csv"'})

    @app.get("/tools", response_class=HTMLResponse)
    def tools_page(request: Request, domain: str = ""):
        return page(request, "tools.html", domain=domain)

    @app.get("/healthz")
    def healthz():
        with conn() as c:
            c.execute("SELECT 1")
        return {"ok": True}

    # --- API -----------------------------------------------------------------------------------------------------

    @app.post("/api/scan")
    def api_scan(body: ScanIn, request: Request):
        # JSON only: a cross-site form or no-cors fetch can't send it without a CORS preflight (which fails)
        if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
            raise HTTPException(415, "Send the request as application/json")
        name = normalize_domain(body.domain, live().internal_zones)
        if not name:
            raise HTTPException(422, "Not a valid domain name")
        request.state.domain = name
        with conn() as c:
            if not users.domain_allowed(c, name):   # domain inventory scope: the original scanner's guardrail
                raise HTTPException(403, f"{name} is outside the configured inventory scope")
            s = admin.effective(settings, c)
            who = admin.client_key(c, client_ip(request))
            limits_off = settings.scan_limits_off or users.get_scope(c).get("scan_limits_off", False)
            if peer_in(request, internal_nets) or limits_off:   # trusted clients, or limits disabled in Settings
                return jobs.enqueue(c, name, client=who)
            last = c.execute("SELECT MAX(s.started) FROM scans s JOIN domains d ON d.id = s.domain_id WHERE d.name = ?",
                             (name,)).fetchone()[0]
            if s.once_per_day and last and last[:10] == db.now()[:10]:
                raise HTTPException(429, f"{name} was already scanned today; the next scan can run tomorrow")
            if jobs.scans_by_client(c, who) >= s.scans_per_hour:
                raise HTTPException(429, f"At most {s.scans_per_hour} scans per hour")
            if jobs.scans_by_client(c, who, minutes=24 * 60) >= s.scans_per_day:
                raise HTTPException(429, f"At most {s.scans_per_day} scans per day")
            if jobs.visitor_scans(c) >= s.scans_per_day_total:
                raise HTTPException(503, "The day's scans are used up; try again tomorrow")
            if jobs.queued(c) >= s.queue_max:
                raise HTTPException(503, "The scan queue is full; try again later")
            return jobs.enqueue(c, name, client=who)

    @app.get("/api/jobs/{job_id}")
    def api_job(job_id: PathId, request: Request):
        with conn() as c:
            job = jobs.get(c, job_id)
        if not job or not scope_of(request).sees(job["domain"]):
            raise HTTPException(404, "No such job")
        return job

    @app.get("/api/domains")
    def api_domains(request: Request, q: str = ""):
        scope = scope_of(request)
        with conn() as c:
            return db.domains_overview(c, q.strip().lower(), scope)

    @app.get("/api/domains/{name}/history")
    def api_history(name: str, request: Request):
        scope = scope_of(request)
        with conn() as c:
            domain_or_404(c, name, scope)
            return db.history(c, name)

    @app.get("/api/scans/{scan_id}")
    def api_scan_records(scan_id: PathId, request: Request):
        scope = scope_of(request)
        with conn() as c:
            s = db.scan(c, scan_id)
            if not s or not scope.sees(s["domain"]):
                raise HTTPException(404, "No such scan")
            return {"scan": s, "records": db.records(c, scan_id)}

    @app.get("/scans/{scan_id}.csv")
    def scan_csv(scan_id: PathId, request: Request):
        scope = scope_of(request)
        with conn() as c:
            s = db.scan(c, scan_id)
            if not s or not scope.sees(s["domain"]):
                raise HTTPException(404, "No such scan")
            rows = db.records(c, scan_id)
        request.state.domain = s["domain"]
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=list(db.RECORD_FIELDS))
        w.writeheader()
        w.writerows({k: csv_safe(v) for k, v in r.items()} for r in rows)
        fname = f"{s['domain']}_{s['started'][:10]}.csv"
        return Response(buf.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="{fname}"'})

    @app.get("/api/rdap/{name}")
    def api_rdap(name: str, request: Request):
        d = normalize_domain(name)
        if not d:
            raise HTTPException(422, "Not a valid domain name")
        limit_lookups(request)
        try:
            return tools.rdap(d, client)
        except (httpx.HTTPError, ValueError) as exc:   # ValueError: a body that isn't JSON
            raise HTTPException(502, f"RDAP lookup failed: {type(exc).__name__}") from None

    @app.get("/api/email/{name}")
    def api_email(name: str, request: Request):
        d = normalize_domain(name)
        if not d:
            raise HTTPException(422, "Not a valid domain name")
        limit_lookups(request)
        return tools.email_security(d)

    add_admin(app, settings, conn, page, client_ip, client)
    return app


NOTICES = {"tuned": "Settings saved; they apply at once.", "cancelled": "Job cancelled.", "retried": "Job queued.",
           "gone": "That job had already finished.", "saved": "Saved.", "user-added": "User created.",
           "tunnel-requested": "Saved. The tunnel settings were handed to the host; its result shows below.",
           "tor-requested": "Handed to the host: the Tor service switches within a few seconds (reload this page).",
           "relays": "Mullvad relay list refreshed.", "route-saved": "Route saved.", "route-deleted": "Route removed.",
           "default-saved": "Preferred route saved: the default for posture scans.",
           "user-saved": "User updated.", "user-deleted": "User removed.", "pw-changed": "Password changed.",
           "2fa-off": "Two-factor turned off.", "pw-set": "Password set; you can sign in now.",
           "posture-queued": "Posture scan queued; reload the page later for the results.",
           "posture-pending": "Those addresses are already queued or running.",
           "import-queued": "CSV import queued; reload the page for its progress.",
           "import-cancelled": "CSV import cancelled; the uploaded file was removed.",
           "schedule-saved": "Schedule saved; its next run is shown below.", "schedule-deleted": "Schedule removed.",
           "schedule-run": "Schedule run queued.", "schedule-on": "Schedule enabled; next run from now.",
           "schedule-off": "Schedule disabled.", "discovery-queued": "Scan with nmap discovery queued.",
           "discovery-open": "A scan of this domain is already queued or running; it keeps its own parameters.",
           "viewer-added": "Viewer added.", "viewer-removed": "Viewer removed.", "rights-saved": "Rights saved."}


def schedule_opts(c, domain: str, internal: bool = False) -> dict:
    """The choices of the schedule form for one domain ('' = not picked yet: no host or tag choices). via: the posture
    profiles whose route is a proxy or VPN (name -> route), for the route note next to the profile pick."""
    hosts = posture.host_list(c, domain) if domain else []
    via = {}
    for p in posture.profiles(c):
        if r := schedules.posture_route(c, p["name"]):
            kind = proxy.KINDS[r["kind"]]
            named = r["kind"] == "custom" or kind.lower() in r["name"].lower()   # no "Tor (Tor)"
            via[p["name"]] = r["name"] if named else f"{r['name']} ({kind})"
    private = internal or any(not proxy.public_address(ip) for h in hosts for ip in h["ips"] if _is_ip(ip))
    note = ""
    if via and (private or not domain):
        where = f"{domain} has private addresses" if domain else "on internal domains and private addresses"
        note = (f"Route check: {where}; posture scans with {', '.join(via)} fail there (Tor and Mullvad never "
                "carry a private address, a proxy usually cannot reach one). Pick a profile with route Direct.")
    return {"posture": posture.profiles(c), "discovery": discovery.profiles(c), "hosts": hosts,
            "tags": sorted({t for h in hosts for t in h["tags"] + h["net_tags"]}), "freqs": schedules.FREQS,
            "weekdays": schedules.WEEKDAYS, "host_modes": schedules.HOST_MODES,
            "default_discovery": discovery.get_default(c), "via": via, "route_note": note,
            "internal": internal}


def new_schedule(opts: dict | None) -> dict:
    """A new schedule form's starting values."""
    if not opts:
        return {}
    return {"name": "Weekly rescan", "enabled": "1", "discovery": "1", "discovery_profile": opts["default_discovery"],
            "posture": "", "posture_profile": posture.DEFAULT_PROFILE, "host_mode": "all", "freq": "weekly",
            "at_time": "03:00", "weekday": "6", "monthday": "1", "every": "1", "chosen": []}


def schedule_form(s: dict) -> dict:
    """A saved schedule as form values."""
    return {**{k: str(s[k]) for k in schedules.COLS if k != "hosts"}, "chosen": json.loads(s["hosts"] or "[]")}


def refused_form(data: dict) -> dict:
    """A refused schedule form as it was sent (unticked boxes stay unticked)."""
    return {**data, "enabled": data.get("enabled", "0"), "chosen": [k[2:] for k in data if k.startswith("h:")]}
PRIVATE = {"Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow"}
PENDING = "__Host-domin_2fa"   # short-lived cookie between the password and the second-factor step
PENDING_MIN = 5


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def add_admin(app: FastAPI, settings: Settings, conn, page, client_ip, http: httpx.Client) -> None:
    """The signed-in area under /admin (behind the optional DOMIN_ADMIN_IPS network allowlist). User accounts with
    roles (admin, power user with per-domain grants: domin.access), optional TOTP second factor, a session cookie and
    a CSRF token per form."""
    base = ADMIN
    cve_db = cve.Database(settings.cve_db_mode, settings.cve_db_file, settings.cve_ttl_days)

    async def form(request: Request, limit: int = 10_000) -> dict[str, str]:
        body = await request.body()
        if len(body) > limit:
            raise HTTPException(413, "Form too large")
        return {k: v[0] for k, v in parse_qs(body.decode("utf-8", "replace")).items()}

    def conn_del(c, key: str):
        c.execute("DELETE FROM kv WHERE key = ?", (key,))

    def current(request: Request, c, data: dict[str, str] | None = None) -> tuple[dict | None, dict | None]:
        """(session, user) for a valid, enabled session, else (None, None); checks CSRF when data is given."""
        s = session_for(c, request, settings)
        if not s:
            return None, None
        if data is not None and not hmac.compare_digest(data.get("csrf", ""), s["csrf"]):
            raise HTTPException(403, "The form expired; reload the page and try again")
        u = users.get(c, s["user_id"]) if s["user_id"] else None
        if not u or u["disabled"]:
            return None, None
        request.state.scope = access.for_user(c, u)   # what this user may see and act on
        return s, u

    def qr_markup(uri: str) -> Markup | str:
        """The pending enrolment's QR code: inline SVG from segno (attributes only, nothing user-typed inside)."""
        return Markup(totp.qr_svg(uri)) if uri else ""

    def priv(resp):
        resp.headers.update(PRIVATE)
        return resp

    def back(path: str = base, notice: str = "") -> RedirectResponse:
        if notice:   # the query goes before a #fragment, else the browser never sends it
            path, hsh, frag = path.partition("#")
            path = f"{path}{'&' if '?' in path else '?'}ok={notice}{hsh}{frag}"
        return priv(RedirectResponse(path, status_code=303))

    def shell(request: Request, name: str, u: dict, s: dict, status: int = 200, **ctx) -> HTMLResponse:
        notice = NOTICES.get(request.query_params.get("ok", ""), "")
        return priv(page(request, name, status, base=base, user=u, csrf=s["csrf"], notice=notice,
                         no_login=s.get("token_hash") == "", **ctx))

    def set_session(resp, c, user_id: int):
        resp.set_cookie(COOKIE, admin.new_session(c, user_id), max_age=admin.SESSION_HOURS * 3600, path="/",
                        secure=True, httponly=True, samesite="strict")

    # --- dashboard and sign-in -----------------------------------------------------------------------------------

    def dashboard(request: Request, c, u: dict, s: dict, error: str = "", status: int = 200) -> HTMLResponse:
        live = admin.effective(settings, c)
        return shell(request, "admin.html", u, s, status, stats=admin.report(c), jobs=jobs.admin_list(c),
                     sched_rows=schedules.listing(c, request.state.scope),
                     tunable=[(k, *v, getattr(live, k)) for k, v in admin.TUNABLE.items()], error=error)

    @app.get(base, response_class=HTMLResponse, include_in_schema=False)
    def admin_page(request: Request):
        nxt = safe_next(request.query_params.get("next"))
        with conn() as c:
            s, u = current(request, c)
            if u and not (nxt and s.get("token_hash") == ""):   # the lab stand-in sent here to sign in for real
                if nxt:
                    return back(nxt)
                if u["role"] == "admin":
                    return dashboard(request, c, u, s)
                can = request.state.scope.can   # a power user's start page: the first feature it may use
                return back(base + "/security" if can("posture") else base + "/security/scans" if can("scans")
                            else "/" if can("inventory") else base + "/account")
            any_user = users.count(c) > 0
        return priv(page(request, "login.html", base=base, any_user=any_user, error="", next=nxt))

    def signed_in(c, u: dict, nxt: str) -> RedirectResponse:
        """After the password (and code): a user who must set up two-factor (role or own tick) goes to My account
        first; else back where the sign-in started, or the start page."""
        users.record_login(c, u["id"])
        resp = back(base + "/account" if users.needs_totp_setup(c, u) else nxt or base)
        set_session(resp, c, u["id"])
        return resp

    @app.post(base + "/login", include_in_schema=False)
    async def admin_login(request: Request):
        data = await form(request)
        nxt = safe_next(data.get("next"))
        with conn() as c:
            who = admin.client_key(c, client_ip(request))
            if admin.login_blocked(c, who):
                return priv(page(request, "login.html", 429, base=base, any_user=users.count(c) > 0,
                                 error="Too many failed sign-ins; wait 15 minutes.", next=nxt))
            u = users.verify_password(c, data.get("name", ""), data.get("password", ""))
            if not u:
                admin.login_failed(c, who)
                return priv(page(request, "login.html", 401, base=base, any_user=users.count(c) > 0,
                                 error="Wrong user name or password.", next=nxt))
            if u["has_totp"]:
                token = secrets.token_urlsafe(24)
                expires = (datetime.now() + timedelta(minutes=PENDING_MIN)).isoformat(timespec="seconds")
                admin.kv_set(c, f"login2fa:{admin._token_hash(token)}",
                             json.dumps({"user_id": u["id"], "expires": expires, "next": nxt}))
                resp = priv(page(request, "totp.html", base=base, error=""))
                # a __Host- cookie needs Path=/ (browsers drop it otherwise); only the /login/totp handler reads it
                resp.set_cookie(PENDING, token, max_age=PENDING_MIN * 60, path="/", secure=True, httponly=True,
                                samesite="strict")
                return resp
            return signed_in(c, u, nxt)

    def _pending(c, token: str | None) -> dict | None:
        """The pending second-factor step: {user_id, expires, next}, or None when unknown or expired."""
        raw = admin.kv_get(c, f"login2fa:{admin._token_hash(token)}") if token else None
        if not raw:
            return None
        data = json.loads(raw)
        return None if data["expires"] < db.now() else data

    @app.post(base + "/login/totp", include_in_schema=False)
    async def admin_login_totp(request: Request):
        data = await form(request)
        token = request.cookies.get(PENDING)
        with conn() as c:
            who = admin.client_key(c, client_ip(request))
            if admin.login_blocked(c, who):
                return priv(page(request, "totp.html", 429, base=base, error="Too many tries; wait 15 minutes."))
            pend = _pending(c, token)
            u = users.get(c, pend["user_id"]) if pend else None
            if not u or u["disabled"]:
                return back()   # expired: start again
            if not users.verify_second_factor(c, u["id"], data.get("code", "")):
                admin.login_failed(c, who)
                return priv(page(request, "totp.html", 401, base=base, error="Wrong code."))
            conn_del(c, f"login2fa:{admin._token_hash(token)}")   # one use
            resp = signed_in(c, u, safe_next(pend.get("next")))
            resp.delete_cookie(PENDING, path="/", secure=True, httponly=True, samesite="strict")
            return resp

    @app.post(base + "/logout", include_in_schema=False)
    async def admin_logout(request: Request):
        data = await form(request)
        with conn() as c:
            s, u = current(request, c, data)
            if s:
                admin.end_session(c, request.cookies.get(COOKIE))
        resp = back()
        resp.delete_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="strict")
        return resp

    # --- set a password from a one-time link (invite or admin reset) ----------------------------------------------

    @app.get(base + "/set-password", response_class=HTMLResponse, include_in_schema=False)
    def set_password_page(request: Request, token: str = ""):
        with conn() as c:
            u = users.setpw_user(c, token)
        if not u:
            return priv(page(request, "setpw.html", 404, base=base, user_name=None, token="", error=""))
        return priv(page(request, "setpw.html", base=base, user_name=u["name"], token=token, error=""))

    @app.post(base + "/set-password", include_in_schema=False)
    async def set_password_submit(request: Request):
        data = await form(request)
        token = data.get("token", "")
        with conn() as c:
            u = users.setpw_user(c, token)
            if not u:
                return priv(page(request, "setpw.html", 404, base=base, user_name=None, token="", error=""))
            pw = data.get("password", "")
            if pw != data.get("confirm", "") or len(pw) < 12:
                return priv(page(request, "setpw.html", 422, base=base, user_name=u["name"], token=token,
                                 error="Use at least 12 characters and type the same password twice."))
            users.use_setpw_token(c, token, pw)
        return back(base, "pw-set")

    # --- account (any signed-in user) ----------------------------------------------------------------------------

    @app.get(base + "/account", response_class=HTMLResponse, include_in_schema=False)
    def account_page(request: Request):
        with conn() as c:
            s, u = current(request, c)
            if not u:
                return back()
            pending = users.enrol_pending(c, u["id"])
            uri = totp.provisioning_uri(pending["secret"], u["name"]) if pending else ""
            must_setup = users.needs_totp_setup(c, u)
        return shell(request, "account.html", u, s, enrol=pending, otpauth=uri, qr=qr_markup(uri),
                     must_setup=must_setup, error="")

    @app.post(base + "/account/password", include_in_schema=False)
    async def account_password(request: Request):
        data = await form(request)
        with conn() as c:
            s, u = current(request, c, data)
            if not u:
                return back()
            who = admin.client_key(c, client_ip(request))   # the sign-in failure counter and lockout apply here too
            if admin.login_blocked(c, who):
                return shell(request, "account.html", u, s, 429, enrol=None, otpauth="", must_setup=False,
                             error="Too many failed tries; wait 15 minutes.")
            if not users.verify_password(c, u["name"], data.get("current", "")):
                admin.login_failed(c, who)
                return shell(request, "account.html", u, s, 401, enrol=None, otpauth="", must_setup=False,
                             error="The current password is wrong.")
            new = data.get("new", "")
            if new != data.get("confirm", "") or len(new) < 12:
                return shell(request, "account.html", u, s, 422, enrol=None, otpauth="", must_setup=False,
                             error="Use at least 12 characters and type the same new password twice.")
            users.set_password(c, u["id"], new)   # signs this browser out too
        return back(base + "/account", "pw-changed")

    @app.post(base + "/account/2fa/start", include_in_schema=False)
    async def account_2fa_start(request: Request):
        data = await form(request)
        with conn() as c:
            s, u = current(request, c, data)
            if not u:
                return back()
            users.start_enrol(c, u["id"])
        return back(base + "/account")

    @app.post(base + "/account/2fa/confirm", include_in_schema=False)
    async def account_2fa_confirm(request: Request):
        data = await form(request)
        with conn() as c:
            s, u = current(request, c, data)
            if not u:
                return back()
            codes = users.confirm_enrol(c, u["id"], data.get("code", ""))
            if codes is None:
                pending = users.enrol_pending(c, u["id"])
                uri = totp.provisioning_uri(pending["secret"], u["name"]) if pending else ""
                return shell(request, "account.html", u, s, 422, enrol=pending, otpauth=uri, qr=qr_markup(uri),
                             must_setup=users.needs_totp_setup(c, u), error="Wrong code; try the current one.")
            u = users.get(c, u["id"])
        return shell(request, "account.html", u, s, enrol=None, otpauth="", must_setup=False, error="",
                     recovery=codes)

    @app.post(base + "/account/2fa/disable", include_in_schema=False)
    async def account_2fa_disable(request: Request):
        data = await form(request)
        with conn() as c:
            s, u = current(request, c, data)
            if not u:
                return back()
            if users.totp_required(c, u):
                return shell(request, "account.html", u, s, 403, enrol=None, otpauth="", must_setup=False,
                             error="Two-factor is required for your account and cannot be turned off.")
            who = admin.client_key(c, client_ip(request))   # re-authentication: current password or a code
            if admin.login_blocked(c, who):
                return shell(request, "account.html", u, s, 429, enrol=None, otpauth="", must_setup=False,
                             error="Too many failed tries; wait 15 minutes.")
            proof = data.get("proof", "")
            if not (users.verify_password(c, u["name"], proof) or users.verify_second_factor(c, u["id"], proof)):
                admin.login_failed(c, who)
                return shell(request, "account.html", u, s, 401, enrol=None, otpauth="", must_setup=False,
                             error="Enter your current password or a code from your authenticator to turn it off.")
            users.disable_totp(c, u["id"])
        return back(base + "/account", "2fa-off")

    # --- users (admin only) --------------------------------------------------------------------------------------

    def admin_only(request: Request, c, data=None):
        s, u = current(request, c, data)
        if not u:
            return None, None, back()
        if u["role"] != "admin":
            raise HTTPException(404, "Not Found")
        return s, u, None

    # A new set-password link is shown once to the admin who made it: kept server-side (kv) under this session, never
    # in a redirect URL (browser history, logs, Referer).
    LINK_MIN = 10

    def link_key(s: dict) -> str:
        return "setpw-link:" + admin._token_hash(s["csrf"])

    def link_keep(c, s: dict, token: str) -> None:
        c.execute("DELETE FROM kv WHERE key LIKE 'setpw-link:%' AND json_extract(value, '$.expires') < ?",
                  (db.now(),))
        expires = (datetime.now() + timedelta(minutes=LINK_MIN)).isoformat(timespec="seconds")
        admin.kv_set(c, link_key(s), json.dumps({"link": f"{base}/set-password?token={token}", "expires": expires}))

    def link_take(c, s: dict) -> str:
        raw = admin.kv_get(c, link_key(s))
        if not raw:
            return ""
        conn_del(c, link_key(s))   # once
        data = json.loads(raw)
        return data["link"] if data["expires"] >= db.now() else ""

    def users_view(request, c, u, s, status: int = 200, error: str = "", link: str = ""):
        rows = users.listing(c)
        return shell(request, "users.html", u, s, status, users=rows, roles=users.ROLES,
                     must_2fa={r["id"]: users.totp_required(c, r) for r in rows},
                     last_admin={r["id"]: users.is_last_admin(c, r["id"]) for r in rows},
                     grants=access.all_grants(c), levels=access.LEVEL_LABELS, audit=access.audit_recent(c),
                     link=link, error=error)

    @app.get(base + "/users", response_class=HTMLResponse, include_in_schema=False)
    def users_page(request: Request):
        with conn() as c:
            s, u, redirect = admin_only(request, c)
            if redirect:
                return redirect
            return users_view(request, c, u, s, link=link_take(c, s))

    def user_edit_view(request, c, u, s, target: dict, status: int = 200, error: str = "",
                       rows: list[dict] | None = None, link: str = ""):
        """One user's role and per-domain grants; rows: a refused form's grant rows, else the saved grants."""
        rows = rows if rows is not None else access.grants(c, target["id"])
        domains = [r["name"] for r in c.execute("SELECT name FROM domains ORDER BY name")]
        return shell(request, "user_edit.html", u, s, status, target=target, roles=users.ROLES,
                     last_admin=users.is_last_admin(c, target["id"]), grant_rows=rows + [{"domain": "",
                     "level": "viewer"}] * 3, domains=domains, levels=access.LEVEL_LABELS, all_domains=access.ALL,
                     role_2fa=users.required_for(c, target["role"]), error=error,
                     features=access.FEATURES, admin_features=access.ADMIN_FEATURES, rights=access.rights_of(target),
                     right_labels=access.RIGHT_LABELS, link=link)

    @app.get(base + "/users/{user_id}", response_class=HTMLResponse, include_in_schema=False)
    def user_edit_page(request: Request, user_id: PathId):
        with conn() as c:
            s, u, redirect = admin_only(request, c)
            if redirect:
                return redirect
            target = users.get(c, user_id)
            if not target:
                raise HTTPException(404, "No such user")
            return user_edit_view(request, c, u, s, target, link=link_take(c, s))

    @app.post(base + "/users/add", include_in_schema=False)
    async def users_add(request: Request):
        data = await form(request)
        with conn() as c:
            s, u, redirect = admin_only(request, c, data)
            if redirect:
                return redirect
            try:
                uid = users.create(c, data.get("name", ""), data.get("role", ""))
            except ValueError as exc:
                return users_view(request, c, u, s, 422, str(exc))
            access.audit(c, u["name"], "user-add", data.get("name", "").strip(), f"role {data.get('role')}")
            link_keep(c, s, users.new_setpw_token(c, uid))
        if data.get("role") == "power":   # next: pick its domains
            return back(f"{base}/users/{uid}", "user-added")
        return back(f"{base}/users", "user-added")

    @app.post(base + "/users/{user_id}/{action}", include_in_schema=False)
    async def users_action(request: Request, user_id: PathId, action: str):
        data = await form(request)
        with conn() as c:
            s, u, redirect = admin_only(request, c, data)
            if redirect:
                return redirect
            target = users.get(c, user_id)
            if not target:
                raise HTTPException(404, "No such user")
            after = base + "/users" + (f"/{user_id}" if data.get("from") == "edit" else "")
            if action == "role":
                role = data.get("role", "")
                if users.is_last_admin(c, user_id) and role != "admin":
                    raise HTTPException(409, "This is the last admin; make another user an admin first")
                try:
                    users.set_role(c, user_id, role)
                except ValueError as exc:
                    raise HTTPException(422, str(exc)) from None
                if role != target["role"]:
                    access.audit(c, u["name"], "role", target["name"], f"{target['role']} -> {role}")
                return back(after, "user-saved")
            if action == "grants":
                try:
                    wanted = access.parse_grants(data)
                except ValueError as exc:
                    rows = [{"domain": data.get(f"g_domain_{i}", ""), "level": data.get(f"g_level_{i}", "viewer")}
                            for i in range(200) if data.get(f"g_domain_{i}")]
                    return user_edit_view(request, c, u, s, target, 422, str(exc), rows)
                diff = access.set_grants(c, user_id, wanted, u["name"])
                detail = "; ".join(f"{k} {', '.join(v)}" for k, v in diff.items() if v)
                if detail:
                    access.audit(c, u["name"], "grants", target["name"], detail)
                return back(f"{base}/users/{user_id}", "user-saved")
            if action == "rights":
                try:
                    wanted = access.parse_rights(data)
                except ValueError as exc:
                    return user_edit_view(request, c, u, s, target, 422, str(exc))
                if changed := access.set_rights(c, user_id, wanted):
                    access.audit(c, u["name"], "rights", target["name"], ", ".join(changed))
                return back(f"{base}/users/{user_id}#rights", "rights-saved")
            if action == "disable":
                want = data.get("disabled") == "on"
                if want and users.is_last_admin(c, user_id):
                    raise HTTPException(409, "This is the last admin; cannot disable it")
                users.set_disabled(c, user_id, want)
                access.audit(c, u["name"], "disable" if want else "enable", target["name"])
                return back(after, "user-saved")
            if action == "reset-2fa":
                users.disable_totp(c, user_id)
                access.audit(c, u["name"], "reset-2fa", target["name"])
                return back(after, "user-saved")
            if action == "require-2fa":
                want = data.get("required") == "on"
                users.set_totp_required(c, user_id, want)
                if want != target["totp_required"]:
                    access.audit(c, u["name"], "require-2fa", target["name"], "on" if want else "off")
                return back(after, "user-saved")
            if action == "reset-password":
                link_keep(c, s, users.new_setpw_token(c, user_id))
                access.audit(c, u["name"], "reset-password", target["name"])
                return back(after, "user-saved")
            if action == "delete":
                if users.is_last_admin(c, user_id):
                    raise HTTPException(409, "This is the last admin; cannot delete it")
                users.delete(c, user_id)
                access.audit(c, u["name"], "delete", target["name"])
                return back(base + "/users", "user-deleted")
        raise HTTPException(404, "Unknown action")

    @app.post(base + "/domains/{name}/delete", include_in_schema=False)
    async def admin_drop_domain(request: Request, name: str):
        data = await form(request)
        with conn() as c:
            s, u, redirect = admin_only(request, c, data)
            if redirect:
                return redirect
            d = normalize_domain(name, admin.effective(settings, c).internal_zones)
            if not d or not db.delete_domain(c, d):
                raise HTTPException(404, "No such domain")
        return back("/")   # the domain is gone from the overview

    # --- viewers on a domain (domain admin of it: access.grant_viewer) -------------------------------------------

    @app.post(base + "/domains/{name}/viewers", include_in_schema=False)
    @app.post(base + "/domains/{name}/viewers/{user_id}/delete", include_in_schema=False)
    async def domain_viewers(request: Request, name: str, user_id: int | None = None):
        data = await form(request)
        with conn() as c:
            s, u = current(request, c, data)
            if not u:
                return back()
            grants = request.state.scope
            d = db.domain(c, name.lower())
            if not d or not grants.sees(d["name"]):   # outside the grants: as an unknown domain
                raise HTTPException(404, f"{name} has not been scanned")
            if not grants.manages(d["name"]):
                raise HTTPException(403, f"Granting viewers needs domain admin rights on {d['name']}.")
            try:
                if user_id is None:
                    if not (data.get("user") or "").isdigit():
                        raise HTTPException(422, "Pick a power user.")
                    access.grant_viewer(c, d["name"], int(data["user"]), u)
                else:
                    access.revoke_viewer(c, d["name"], user_id, u)
            except LookupError as e:
                raise HTTPException(404, str(e)) from None
            except ValueError as e:
                raise HTTPException(409, str(e)) from None
        return back(f"/d/{d['name']}#viewers", "viewer-removed" if user_id else "viewer-added")

    # --- settings / scope (admin only) ---------------------------------------------------------------------------

    def settings_view(request, c, u, s, scope, status=200, error=""):
        countries = sorted(set(users.inventory_countries(c)) | set(scope["countries_allow"])
                           | set(scope["countries_deny"]))
        eff = admin.effective(settings, c)
        return shell(request, "settings.html", u, s, status, scope=scope,
                     raw_ok=admin.kv_get(c, posture.RAW_KEY) == "1",
                     inv_counts=users.inventory_in_scope(c, scope), posture_counts=users.posture_in_scope(c, scope),
                     countries=countries, roles=users.ROLES, error=error,
                     internal_zones=eff.internal_zones, internal_dns=eff.internal_dns, internal_nets=eff.internal_nets,
                     csv_import=csvimport.status(c), csv_max_mb=csvimport.MAX_BYTES // (1024 * 1024),
                     allow_no_login=settings.allow_no_login, no_login_on=admin.no_login_session(c) is not None,
                     signin=users.signin_required(c))

    @app.post(base + "/settings/signin", include_in_schema=False)
    async def settings_signin(request: Request):
        """Where sign-in is required: inventory pages, posture (the lab stand-in; elsewhere posture always needs it)."""
        data = await form(request)
        with conn() as c:
            s, u, redirect = admin_only(request, c, data)
            if redirect:
                return redirect
            old = users.signin_required(c)
            new = {"inventory": data.get("inventory") == "on",
                   "posture": data.get("posture") == "on" or not settings.allow_no_login}
            users.set_signin_required(c, **new)
            if new != old:
                access.audit(c, u["name"], "sign-in", "settings",
                             ", ".join(f"{k} {'required' if v else 'open'}" for k, v in new.items()))
        return back(base + "/settings#signin", "saved")

    @app.post(base + "/settings/no-login", include_in_schema=False)
    async def settings_no_login(request: Request):
        """Dev/lab only (DOMIN_ALLOW_NO_LOGIN): turn sign-in off (everyone acts as this admin) or back on."""
        data = await form(request)
        with conn() as c:
            s, u, redirect = admin_only(request, c, data)
            if redirect:
                return redirect
            if not settings.allow_no_login:
                raise HTTPException(403, "Sign-in can only be turned off with DOMIN_ALLOW_NO_LOGIN=1.")
            off = data.get("off") == "1"
            admin.set_no_login(c, u["id"] if off else None, s["csrf"])
            # the old switch's meaning: off opens posture to the stand-in too, on requires sign-in there again
            users.set_signin_required(c, users.signin_required(c)["inventory"], not off)
        return back(base + "/settings", "saved")

    @app.post(base + "/settings/csv-import", include_in_schema=False)
    async def settings_csv_import(request: Request):
        """Upload a CSV export (All records or a search download): streamed to a temp file in the data directory
        (csvimport.MAX_BYTES at most), then queued for the worker; the page shows its progress."""
        with conn() as c:
            s, u, redirect = admin_only(request, c)   # CSRF: the token is in the multipart body, checked below
            if redirect:
                return redirect
            if csvimport.busy(c):
                raise HTTPException(409, "An import is already queued or running; wait for it to finish.")
        try:
            fields, path, name = await csvimport.receive(request, settings.db_path.parent)
        except csvimport.TooLarge:
            raise HTTPException(413, f"The file is larger than {csvimport.MAX_BYTES // (1024 * 1024)} MB.") from None
        except ValueError as e:
            raise HTTPException(400, str(e)) from None
        if not hmac.compare_digest(fields.get("csrf", ""), s["csrf"]):
            if path:
                path.unlink(missing_ok=True)
            raise HTTPException(403, "The form expired; reload the page and try again")
        if not path or not path.stat().st_size:
            if path:
                path.unlink(missing_ok=True)
            raise HTTPException(422, "Pick a CSV file.")
        try:
            layout = await run_in_threadpool(csvimport.inspect, path)
        except (ValueError, csvimport.TooLarge) as e:
            path.unlink(missing_ok=True)
            raise HTTPException(422, f"Cannot read {name or 'the file'}: {e}.") from None
        with conn() as c:
            csvimport.sweep(c, settings.db_path.parent)
            token = csvimport.hold(c, path, name, u["id"], s["token_hash"], layout)
        return back(f"{base}/settings/csv-import/map?t={token}")

    def held_upload(c, s, u, token: str) -> dict:
        up = csvimport.held(c, token, u["id"], s["token_hash"], settings.db_path.parent)
        if not up:
            raise HTTPException(404, "This upload has expired or is not yours; upload the file again.")
        return up

    def csv_map_view(request, c, u, s, token: str, up: dict, mapping: dict, header: bool, error: str = "",
                     status: int = 200):
        lay = up["layout"]
        return shell(request, "csv_map.html", u, s, status, token=token, file=up["file"], layout=lay,
                     columns=lay["columns"], mapping=mapping, header=header, targets=csvimport.TARGETS,
                     labels=csvimport.LABELS, hints=csvimport.HINTS,
                     delimiter=csvimport.DELIMITERS.get(lay["delimiter"], lay["delimiter"]),
                     expires=datetime.fromtimestamp(up["at"] + csvimport.UPLOAD_TTL).isoformat(" ", "minutes"),
                     error=error)

    @app.get(base + "/settings/csv-import/map", response_class=HTMLResponse, include_in_schema=False)
    def settings_csv_map(request: Request, t: str = ""):
        """Step 2 of the CSV import: which column feeds which field (pre-filled from the header names)."""
        with conn() as c:
            s, u, redirect = admin_only(request, c)
            if redirect:
                return redirect
            up = held_upload(c, s, u, t)
            lay = up["layout"]
            mapping = csvimport.auto_map(lay["columns"]) if lay["header"] else dict.fromkeys(csvimport.TARGETS)
            return csv_map_view(request, c, u, s, t, up, mapping, lay["header"])

    @app.post(base + "/settings/csv-import/map", include_in_schema=False)
    async def settings_csv_map_post(request: Request):
        """Step 3: import with the chosen mapping (queued for the worker), or cancel (the file is removed)."""
        data = await form(request)
        token = data.get("t", "")
        with conn() as c:
            s, u, redirect = admin_only(request, c, data)
            if redirect:
                return redirect
            up = held_upload(c, s, u, token)
            data_dir = settings.db_path.parent
            if data.get("action") == "cancel":
                csvimport.drop(c, token, data_dir)
                return back(base + "/settings#csv-import", "import-cancelled")
            lay = up["layout"]
            mapping, error = {}, ""
            for t in csvimport.TARGETS:
                v = data.get("map_" + t, "")
                mapping[t] = int(v) if v.isdigit() and int(v) < len(lay["columns"]) else None
                if v and mapping[t] is None:
                    error = "The form names a column the file does not have."
            header = data.get("header") == "on"
            error = error or csvimport.check_mapping(mapping, len(lay["columns"]))
            if error:
                return csv_map_view(request, c, u, s, token, up, mapping, header,
                                    error=error[:1].upper() + error[1:] + ".", status=422)
            if csvimport.busy(c):
                raise HTTPException(409, "An import is already queued or running; wait for it to finish.")
            csvimport.queue(c, Path(up["path"]), up["file"], u["name"], mapping, {**lay, "header": header})
            csvimport.drop(c, token, data_dir, keep_file=True)
        return back(base + "/settings#csv-import", "import-queued")

    @app.get(base + "/settings", response_class=HTMLResponse, include_in_schema=False)
    def settings_page(request: Request):
        with conn() as c:
            s, u, redirect = admin_only(request, c)
            if redirect:
                return redirect
            return settings_view(request, c, u, s, users.get_scope(c))

    @app.post(base + "/settings", include_in_schema=False)
    async def settings_save(request: Request):
        data = await form(request)
        with conn() as c:
            s, u, redirect = admin_only(request, c, data)
            if redirect:
                return redirect
            try:
                scope = users.parse_scope(c, data)
                if "internal_zones" in data:
                    admin.save_internal_dns(c, data.get("internal_zones", ""), data.get("internal_dns", ""),
                                            data.get("internal_nets", ""))
            except ValueError as exc:
                return settings_view(request, c, u, s, users.get_scope(c), 422, str(exc))
            users.save_scope(c, scope)
        return back(base + "/settings", "saved")

    # --- security portal: CVE scan tool (view: any signed-in user; run: domain admin rights) ------------------------

    def security_ctx(status: int = 200, result: dict | None = None, form: dict | None = None,
                     error: str = "", host_result: dict | None = None):
        return {"status": status, "result": result, "host_result": host_result, "form": form or {},
                "error": error, "cve_source": cve.SOURCE, "cve_mode": settings.cve_db_mode,
                "cve_db": str(settings.cve_db_file), "cve_ttl": settings.cve_ttl_days,
                "cve_count": cve_db.size(), "default_ports": fingerprint.DEFAULT_PORTS}

    def security_view(request, u, s, ctx, tab: str = "overview"):
        dom = ctx.pop("posture_domain", None)
        if dom is None:
            dom = request.query_params.get("domain", "")
        host = request.query_params.get("host", "")
        grants = request.state.scope
        with conn() as c:
            known = posture.domains(c, grants)
            dom = dom if dom in known else ""   # unknown or outside the grants: all (granted) domains
            hosts = posture.hosts(c, dom) if dom else []
            host = host if host in hosts else ""
            rep = posture.report(posture.current(c, dom, scope=grants), host)
            rep["charts"]["trend"] = posture.trend(c, dom, host, grants)
            if not dom:   # all domains: the public footprint over time (inventory scans)
                since = (datetime.now() - timedelta(days=posture.TREND_DAYS)).strftime("%Y-%m-%d")
                rep["charts"]["footprint"] = db.footprint_per_day(c, since, grants)
            rep["changes"] = posture.changes(c, dom, host, scope=grants)
            at = json.loads(admin.kv_get(c, jobs.CVE_REFRESH_KEY) or "{}").get("at")
            rep["cve_refreshed"] = datetime.fromtimestamp(at).strftime("%Y-%m-%d %H:%M") if at else ""
            routes = proxy.get(c)
            default = posture.profile(c, posture.DEFAULT_PROFILE) or {}
            ctx.update(tab=ctx.get("tab", tab), posture_domains=known, posture_domain=dom, posture_hosts=hosts,
                       posture_host=host,
                       # one row per address (names sharing it merged), worst severity first (rank 0 = critical;
                       # never scanned last), then by name
                       host_list=posture.by_address(sorted(
                           (h for h in posture.with_results(posture.host_list(c, dom), rep["rows"])
                            if not host or h["host"] == host), key=lambda h: (h["rank"], h["host"])))
                       if dom else [],
                       domain_rows=[] if dom else posture.domain_summary(rep["rows"]),
                       report=rep, profiles=posture.profiles(c), route_names=proxy.names(routes, proxy.tests(c)),
                       scan_route=proxy.label(routes, default.get("route", "")),
                       show_notice=not admin.kv_get(c, f"dismiss:auth-notice:{u['id']}"))
            if ctx["tab"] == "scans":
                ctx.update(schedule_section(c, grants, dom))
        return shell(request, "security.html", u, s, ctx.pop("status", 200), **ctx)

    def internal_check(c):
        zones = admin.effective(settings, c).internal_zones
        return lambda name: is_internal(name, zones)

    def schedule_rows(c, rows: list[dict]) -> list[dict]:
        """Schedules for a list, each with its route warning (route_warn, '' = none)."""
        inside = internal_check(c)
        return [{**r, "route_warn": schedules.route_warning(c, r, inside(r["domain"]))} for r in rows]

    def schedule_section(c, grants: access.Scope, dom: str) -> dict:
        """Posture · Scans, Scheduled rescans: the schedules of the domains in the scope (dom: that one only); the add
        form's domain picker lists the domains this user is domain admin of (none: no form)."""
        rows = [r for r in schedules.listing(c, grants) if not dom or r["domain"] == dom]
        mine = [d for d in posture.domains(c, grants) if grants.acts("scans", d)]
        pick = dom if dom in mine else ""
        opts = schedule_opts(c, pick, internal_check(c)(pick) if pick else False) if mine else None
        return {"sched_rows": schedule_rows(c, rows), "sched_domains": mine, "sched_pick": pick,
                "sched_opts": opts, "new_schedule": new_schedule(opts)}

    @app.post(base + "/security/dismiss-notice", include_in_schema=False)
    async def dismiss_notice(request: Request):
        """Hide the authorised-use banner for this user, for good."""
        data = await form(request)
        with conn() as c:
            s, u = current(request, c, data)
            if not u:
                return back()
            admin.kv_set(c, f"dismiss:auth-notice:{u['id']}", db.now())
        return back(f"{base}/security/scans")

    def lookup_view(request, u, s, ctx):
        with conn() as c:
            route = proxy.label(proxy.get(c))   # ad-hoc fingerprints take the default route
        return shell(request, "lookup.html", u, s, ctx.pop("status", 200), scan_route=route, **ctx)

    @app.get(base + "/security/lookup", response_class=HTMLResponse, include_in_schema=False)
    def lookup_page(request: Request):
        with conn() as c:
            s, u = current(request, c)
            if not u:
                return back()
        return lookup_view(request, u, s, security_ctx())

    @app.get(base + "/security/domain-search", include_in_schema=False)
    def security_domain_search(request: Request):
        """The Posture domain picker's search box: the domains whose data holds every typed word (JSON)."""
        with conn() as c:
            _, u = current(request, c)
            if not u:
                return JSONResponse({"error": "Sign in first."}, status_code=401)
            return JSONResponse({"domains": posture.search_domains(c, request.query_params.get("q", "")[:200],
                                                                   request.state.scope)})

    @app.get(base + "/security/kpis", response_class=HTMLResponse, include_in_schema=False)
    def security_kpis(request: Request):
        """The posture KPIs for what the page's Filter box leaves (domain, host and q as on the page): HTML section."""
        q = request.query_params.get("q", "")[:200].strip()
        dom, host = request.query_params.get("domain", ""), request.query_params.get("host", "")
        with conn() as c:
            s, u = current(request, c)
            if not u:
                return HTMLResponse("", status_code=401)
            grants = request.state.scope
            dom = dom if dom in posture.domains(c, grants) else ""
            rows = posture.narrow(c, posture.report(posture.current(c, dom, scope=grants), host)["rows"], dom, q,
                                  grants)
            rep = posture.report(rows)
        tab = request.query_params.get("tab", "")
        return shell(request, "_posture_kpis.html", u, s, rep=rep, filter=q,
                     tab=tab if tab in ("overview", "analysis") else "overview")

    @app.post(base + "/security/report", include_in_schema=False)
    async def security_report(request: Request):
        """Download a posture report (reports.py) on the ticked host names of one domain: format=pdf or md. Any
        signed-in user (it shows what the posture page shows)."""
        data = await form(request, 200_000)   # every domain ticked: hundreds of names

        def split(key: str) -> list[str]:
            return [x.strip().lower() for x in (data.get(key) or "").split(",") if x.strip()]
        with conn() as c:
            _, u = current(request, c, data)
            if not u:
                return back()
            known = set(posture.domains(c, request.state.scope))   # outside the grants = unknown
            dom = (data.get("domain") or "").strip().lower()
            if data.get("domains") is not None:   # the all-domains view: whole domains
                picks = {d: None for d in split("domains") if d in known}
            else:                                 # one domain's ticked host names
                picks = {dom: split("hosts")} if dom in known and split("hosts") else {}
            if not picks:
                raise HTTPException(422, "Tick at least one domain or host name.")
            m = reports.build(c, picks, u["name"])
        if not m["hosts"]:
            raise HTTPException(422, "None of the ticked names have hosts in the inventory.")
        ext = "pdf" if data.get("format") == "pdf" else "md"
        if ext == "pdf":
            body, kind = await run_in_threadpool(reports.pdf, m), "application/pdf"
        else:
            body, kind = reports.markdown(m).encode(), "text/markdown; charset=utf-8"
        return priv(Response(body, media_type=kind, headers={
            "Content-Disposition": f'attachment; filename="{reports.filename(m, ext)}"'}))

    @app.get(base + "/security", response_class=HTMLResponse, include_in_schema=False)
    def security_page(request: Request):
        with conn() as c:
            s, u = current(request, c)
            if not u:
                return back()
        return security_view(request, u, s, security_ctx())

    # Posture sub-tabs: Overview (the "what", above), Analysis (the "where": domains, hosts), Scans (run + progress)
    for _tab in ("analysis", "scans"):
        def security_tab(request: Request, _tab=_tab):
            with conn() as c:
                s, u = current(request, c)
                if not u:
                    return back()
            return security_view(request, u, s, security_ctx(), _tab)
        app.get(base + "/security/" + _tab, response_class=HTMLResponse, include_in_schema=False)(security_tab)

    @app.post(base + "/security/posture", include_in_schema=False)
    async def security_posture(request: Request):
        """Stage 2: queue posture scans for a whole domain (its in-scope addresses), one host name or one address
        (Renew). Domain admin of that domain; the worker runs them. With `Accept: application/json` (the page's
        script) the answer is JSON: the batch (row ids) for the progress dialog, or the error."""
        data = await form(request)
        as_json = "application/json" in request.headers.get("accept", "")
        with conn() as c:
            s, u = current(request, c, data)
            if not u:
                return priv(JSONResponse({"error": "Sign in again."}, status_code=401)) if as_json else back()
            dom = (data.get("domain") or "").strip().lower()
            host = (data.get("host") or "").strip().lower()
            ip = (data.get("ip") or "").strip()
            prof = posture.profile(c, (data.get("profile") or "").strip() or posture.DEFAULT_PROFILE)

            def refuse(status: int, error: str):
                if as_json:
                    return priv(JSONResponse({"error": error}, status_code=status))
                return security_view(request, u, s, security_ctx(status, error=error, form=data) | {"tab": "scans",
                    "posture_domain": dom})
            grants = request.state.scope
            if dom not in posture.domains(c, grants):   # unknown, or outside the grants: the same answer
                return refuse(422, "Pick a domain with a finished inventory scan.")
            if not grants.manages(dom):
                return refuse(403, f"Running a posture scan needs domain admin rights on {dom}.")
            if not prof:
                return refuse(422, "Pick an existing scan profile.")
            ports = (data.get("ports") or "").strip()   # optional override of the profile's ports
            if ports and not fingerprint.valid_ports(ports):
                return refuse(422, "Ports: digits, commas and hyphens only (e.g. 22,80,443 or 1-1024).")
            prof = {**prof, "ports": ports or prof["ports"]}
            picked = None   # "Scan now" on the host list: the ticked host names, comma separated
            if data.get("picked"):   # set by the dialog, so an empty tick list never widens to the whole domain
                picked = {h.strip().lower() for h in (data.get("hosts") or "").split(",") if h.strip()}
                if not picked:
                    return refuse(422, "Tick at least one host name to scan.")
            found, skipped = posture.targets(c, dom, host=host, ip=ip, names=picked,
                                             ok=netscope.checker(c, settings))
            if not found:
                what = host or ip or (f"the {len(picked)} ticked host name(s)" if picked else dom)
                why = (f" ({skipped} address(es) outside the posture scope or on its Never scan list; see Settings)"
                       if skipped else "")
                return refuse(422, f"No address of {what} to scan{why}.")
            batch: list[int] = []
            n = posture.enqueue(c, dom, found, prof, u["name"], batch)
        notice = "posture-queued" if n else "posture-pending"
        if as_json:
            return priv(JSONResponse({"batch": batch, "queued": n, "domain": dom, "notice": NOTICES[notice]}))
        return back(f"{base}/security/scans?domain={dom}", notice)

    @app.get(base + "/security/posture/status", include_in_schema=False)
    def security_posture_status(request: Request):
        """Progress of posture scans for the progress dialog (any signed-in user): ids=1,2,3 (a batch), plus with
        pending=1 the queued and running rows of `domain` (all domains when empty)."""
        with conn() as c:
            s, u = current(request, c)
            if not u:
                return priv(JSONResponse({"error": "Sign in again."}, status_code=401))
            q, grants = request.query_params, request.state.scope
            ids = {int(x) for x in q.get("ids", "").split(",")[:5000] if x.strip().isdigit()}
            if q.get("pending"):
                ids.update(posture.pending_ids(c, (q.get("domain") or "").strip().lower(), grants))
            if q.get("recent"):   # the Scans tab's activity board: pending plus finished in the last 24 h
                ids.update(posture.recent_ids(c, (q.get("domain") or "").strip().lower(), scope=grants))
            return priv(JSONResponse(posture.progress(c, sorted(ids), grants)))

    @app.post(base + "/tags", include_in_schema=False)
    async def host_tag(request: Request):
        """Add or remove one tag on host names of a domain (domain admin of that domain; host = one name, or several
        joined by "," for a posture row of names sharing an address), then back to the domain page."""
        data = await form(request)
        dom = (data.get("domain") or "").strip().lower()
        names = [h.strip() for h in (data.get("host") or "").lower().split(",") if h.strip()][:50]
        tag = (data.get("tag") or "").strip().lower()
        with conn() as c:
            s, u = current(request, c, data)
            if not u:
                return back()
            grants = request.state.scope
            if not grants.sees(dom):   # outside the grants: as an unknown host
                raise HTTPException(404, "No such host in that domain's latest scan")
            if not grants.manages(dom):
                raise HTTPException(403, f"Tagging hosts needs domain admin rights on {dom}.")
            if not tags.valid(tag):
                raise HTTPException(422, "Tag: 1-30 lower-case letters, digits or -.")
            for host in names or [""]:
                if not c.execute(f"""SELECT 1 FROM records r JOIN ({db.LATEST}) s ON s.id = r.scan_id
                                     JOIN domains d ON d.id = s.domain_id WHERE d.name = ? AND r.host = ?""",
                                 (dom, host)).fetchone():
                    raise HTTPException(404, "No such host in that domain's latest scan")
            for host in names:
                if data.get("action") == "remove":
                    tags.remove(c, host, tag)
                else:
                    tags.add(c, host, tag, u["name"])
        if data.get("from") == "posture":   # the posture view's Host names table: back to that table
            return back(f"{base}/security/analysis?{urlencode({'domain': dom})}#posture-hosts")
        return back(f"/d/{dom}#records")

    def profiles_view(request, u, s, status: int = 200, error: str = "", form: dict | None = None):
        with conn() as c:
            rows = posture.profiles(c)
            routes = proxy.names(proxy.get(c), proxy.tests(c))
        return shell(request, "profiles.html", u, s, status, profiles=rows, error=error, form=form or {},
                     default_ports=fingerprint.DEFAULT_PORTS, route_names=routes)

    @app.get(base + "/security/profiles", response_class=HTMLResponse, include_in_schema=False)
    def profiles_page(request: Request):
        with conn() as c:
            s, u = current(request, c)
            if not u:
                return back()
            # ?edit=<name>: the form starts with that profile's values; saving under the same name replaces it
            p = posture.profile(c, request.query_params.get("edit", "")) or {}
        form = {k: str(p.get(k) if p.get(k) is not None else "") for k in
                ("name", "ports", "note", "intensity", "timing", "timeout", "route")} if p else {}
        return profiles_view(request, u, s, form=form)

    @app.post(base + "/security/profiles", include_in_schema=False)
    async def profiles_save(request: Request):
        """Add or change a scan profile (admins)."""
        data = await form(request)
        with conn() as c:
            s, u = current(request, c, data)
            if not u:
                return back()
            if not request.state.scope.can("profiles", "write"):
                return profiles_view(request, u, s, 403, "Changing scan profiles needs read-write on Scan profiles.",
                                     data)
            p, error = posture.check_profile((data.get("name") or "").strip().lower(),
                                             (data.get("ports") or "").strip(), data.get("intensity"),
                                             data.get("timing"), data.get("timeout"), (data.get("route") or "").strip(),
                                             {r["id"] for r in proxy.get(c)["routes"]})
            if not p:
                return profiles_view(request, u, s, 422, error, data)
            posture.save_profile(c, p, (data.get("note") or "").strip(), u["name"])
        return back(f"{base}/security/profiles")

    @app.post(base + "/security/profiles/{name}/delete", include_in_schema=False)
    async def profiles_delete(request: Request, name: str):
        data = await form(request)
        with conn() as c:
            s, u = current(request, c, data)
            if not u:
                return back()
            if not request.state.scope.can("profiles", "write"):
                return profiles_view(request, u, s, 403, "Changing scan profiles needs read-write on Scan profiles.")
            if uses := posture.profile_used_by(c, name):
                return profiles_view(request, u, s, 409, f"{name} is used by schedule(s) {', '.join(uses)}: pick "
                                     "another profile there first.")
            if not posture.delete_profile(c, name):
                return profiles_view(request, u, s, 422, "The default profile cannot be deleted.")
        return back(f"{base}/security/profiles")

    # --- discovery profiles (nmap stage of inventory scans; admins edit, anyone signed in reads) -------------------

    disc_page = base + "/security/discovery-profiles"

    def discovery_view(request, c, u, s, status: int = 200, error: str = "", form: dict | None = None,
                       editing: bool = False):
        raw_ok = admin.kv_get(c, posture.RAW_KEY) == "1" and users.get_scope(c)["raw_scans"]
        rows = [{**p, "command": discovery.command_line(p, raw=raw_ok), "used_by": discovery.used_by(c, p["name"])}
                for p in discovery.profiles(c)]
        return shell(request, "discovery_profiles.html", u, s, status, profiles=rows, error=error, form=form or {},
                     editing=editing, methods=discovery.METHODS, port_modes=discovery.PORT_MODES, raw_ok=raw_ok,
                     probe_max=discovery.PROBE_MAX, ports_max=discovery.PORTS_MAX, default=discovery.get_default(c),
                     route_names=proxy.names(proxy.get(c), proxy.tests(c)))

    @app.get(disc_page, response_class=HTMLResponse, include_in_schema=False)
    def discovery_page(request: Request):
        with conn() as c:
            s, u = current(request, c)
            if not u:
                return back()
            p = discovery.profile(c, request.query_params.get("edit", "")) or {}
            form = {k: str(p[k]) for k in discovery.FIELDS} if p else {}
            return discovery_view(request, c, u, s, form=form, editing=bool(p))

    @app.post(disc_page, include_in_schema=False)
    async def discovery_save(request: Request):
        data = await form(request)
        with conn() as c:
            s, u = current(request, c, data)
            if not u:
                return back()
            if not request.state.scope.can("discovery", "write"):
                return discovery_view(request, c, u, s, 403, "Changing discovery profiles needs read-write on "
                                      "Discovery profiles.")
            raw_ok = admin.kv_get(c, posture.RAW_KEY) == "1" and users.get_scope(c)["raw_scans"]
            p, error = discovery.check(data, {r["id"] for r in proxy.get(c)["routes"]}, raw_ok)
            if not p:
                return discovery_view(request, c, u, s, 422, error, data)
            discovery.save(c, p, u["name"])
            access.audit(c, u["name"], "discovery-profile-save", p["name"], discovery.command_line(p, raw_ok))
        return back(disc_page, "saved")

    @app.post(disc_page + "/default", include_in_schema=False)
    async def discovery_default(request: Request):
        data = await form(request)
        with conn() as c:
            s, u = current(request, c, data)
            if not u:
                return back()
            if not request.state.scope.can("discovery", "write"):
                return discovery_view(request, c, u, s, 403, "Changing discovery profiles needs read-write on "
                                      "Discovery profiles.")
            name = (data.get("name") or "").strip()
            try:
                discovery.set_default(c, name)
            except ValueError as exc:
                return discovery_view(request, c, u, s, 422, str(exc))
            access.audit(c, u["name"], "discovery-profile-default", name or "(none)", "")
        return back(disc_page, "saved")

    @app.post(disc_page + "/{name}/delete", include_in_schema=False)
    async def discovery_delete(request: Request, name: str):
        data = await form(request)
        with conn() as c:
            s, u = current(request, c, data)
            if not u:
                return back()
            if not request.state.scope.can("discovery", "write"):
                return discovery_view(request, c, u, s, 403, "Changing discovery profiles needs read-write on "
                                      "Discovery profiles.")
            if why := discovery.delete(c, name):
                return discovery_view(request, c, u, s, 409 if "used by" in why else 422, why)
            access.audit(c, u["name"], "discovery-profile-delete", name, "")
        return back(disc_page, "saved")

    @app.post(base + "/discovery/scan", include_in_schema=False)
    async def discovery_scan(request: Request):
        """"Scan with nmap" on a domain page: an inventory scan with a discovery stage (domain admin of the domain)."""
        data = await form(request)
        dom = (data.get("domain") or "").strip().lower()
        with conn() as c:
            s, u = current(request, c, data)
            if not u:
                return back()
            grants = request.state.scope
            if not db.domain(c, dom) or not grants.sees(dom):
                raise HTTPException(404, f"{dom} has not been scanned")
            if not grants.manages(dom):
                raise HTTPException(403, f"Scanning needs domain admin rights on {dom}.")
            if not users.domain_allowed(c, dom):
                raise HTTPException(403, f"{dom} is outside the inventory scope (Settings).")
            name = (data.get("profile") or "").strip()
            if not discovery.profile(c, name):
                raise HTTPException(422, "Pick an existing discovery profile.")
            busy = c.execute("SELECT 1 FROM jobs WHERE domain = ? AND status IN ('queued', 'running')",
                             (dom,)).fetchone()
            job = jobs.enqueue(c, dom, client="admin", discovery=name)
            access.audit(c, u["name"], "discovery-scan", dom, f"profile {name}, job {job['id']}"
                         + (" (joined the open job)" if busy else ""))
        return back(f"/d/{dom}", "discovery-open" if busy else "discovery-queued")

    # --- schedules (domin.schedules): domain admins on their domains, viewers read, outside = 404 ------------------

    def schedule_or_404(c, sid: int, grants: access.Scope) -> dict:
        sc = schedules.get(c, sid)
        if not sc or not grants.sees(sc["domain"]):
            raise HTTPException(404, "No such schedule")
        return sc

    def schedule_view(request, c, u, s, dom: str, sid: int | None, sf: dict, status: int = 200, error: str = "",
                      route_warn: str = ""):
        grants = request.state.scope
        rows = [r for r in schedules.for_domain(c, dom) if r["id"] == sid] if sid else []
        return shell(request, "schedule.html", u, s, status, error=error, sf=sf, sf_id=sid, sched_domain=dom,
                     sched_rows=schedule_rows(c, rows), can_manage=grants.acts("scans", dom), route_warn=route_warn,
                     sched_opts=schedule_opts(c, dom, internal_check(c)(dom)) if grants.acts("scans", dom) else None)

    def schedules_page(dom: str = "") -> str:
        """Posture · Scans, Scheduled rescans (filtered to dom)."""
        return f"{base}/security/scans" + (f"?domain={quote(dom)}" if dom else "") + "#schedules"

    def route_refused(c, dom: str, p: dict, data: dict) -> str:
        """The route warning that stops a save until "Save anyway" is ticked ('' = save)."""
        if data.get("route_ack") in ("1", "on"):
            return ""
        return schedules.route_warning(c, {**p, "domain": dom}, internal_check(c)(dom))

    def schedule_rights(request, c, dom: str) -> None:
        grants = request.state.scope
        if not db.domain(c, dom) or not grants.sees(dom):
            raise HTTPException(404, f"{dom} has not been scanned")
        if not grants.manages(dom):
            raise HTTPException(403, f"Schedules need domain admin rights on {dom}.")

    @app.get(base + "/schedules/{sid}", response_class=HTMLResponse, include_in_schema=False)
    def schedule_page(request: Request, sid: PathId):
        with conn() as c:
            s, u = current(request, c)
            if not u:
                return back()
            sc = schedule_or_404(c, sid, request.state.scope)
            return schedule_view(request, c, u, s, sc["domain"], sid, schedule_form(sc))

    @app.post(base + "/schedules", include_in_schema=False)
    async def schedule_create(request: Request):
        data = await form(request, limit=300_000)   # one h:<name> box per chosen host
        dom = (data.get("domain") or "").strip().lower()
        with conn() as c:
            s, u = current(request, c, data)
            if not u:
                return back()
            schedule_rights(request, c, dom)
            p, error = schedules.check(c, dom, data)
            if not p:
                return schedule_view(request, c, u, s, dom, None, refused_form(data), 422, error)
            if warn := route_refused(c, dom, p, data):
                return schedule_view(request, c, u, s, dom, None, refused_form(data), 409, route_warn=warn)
            sid = schedules.create(c, dom, p, u["name"])
            access.audit(c, u["name"], "schedule-create", dom, f"#{sid} {p['name']}")
        return back(schedules_page(dom), "schedule-saved")

    @app.post(base + "/schedules/{sid}", include_in_schema=False)
    async def schedule_update(request: Request, sid: PathId):
        data = await form(request, limit=300_000)
        with conn() as c:
            s, u = current(request, c, data)
            if not u:
                return back()
            sc = schedule_or_404(c, sid, request.state.scope)
            schedule_rights(request, c, sc["domain"])
            p, error = schedules.check(c, sc["domain"], data)
            if not p:
                return schedule_view(request, c, u, s, sc["domain"], sid, refused_form(data), 422, error)
            if warn := route_refused(c, sc["domain"], p, data):
                return schedule_view(request, c, u, s, sc["domain"], sid, refused_form(data), 409, route_warn=warn)
            schedules.update(c, sid, p, u["name"])
            access.audit(c, u["name"], "schedule-update", sc["domain"], f"#{sid} {p['name']}")
        return back(schedules_page(sc["domain"]), "schedule-saved")

    @app.post(base + "/schedules/{sid}/{action}", include_in_schema=False)
    async def schedule_action(request: Request, sid: PathId, action: str):
        if action not in ("delete", "run", "enabled"):
            raise HTTPException(404, "Not Found")
        data = await form(request)
        with conn() as c:
            s, u = current(request, c, data)
            if not u:
                return back()
            sc = schedule_or_404(c, sid, request.state.scope)
            dom = sc["domain"]
            schedule_rights(request, c, dom)
            if action == "delete":
                schedules.delete(c, sid)
                notice = "schedule-deleted"
            elif action == "enabled":
                on = data.get("on") == "1"
                schedules.set_enabled(c, sid, on, u["name"])
                notice = "schedule-on" if on else "schedule-off"
            else:
                run = schedules.run_now(c, sid)
                if run is None:
                    raise HTTPException(409, "The previous run of this schedule is still queued or running.")
                notice = "schedule-run"
            access.audit(c, u["name"], f"schedule-{action}", dom, f"#{sid} {sc['name']}"
                         + (f": {run['result']}" if action == "run" else f" on={data.get('on')}" if action == "enabled"
                            else ""))
        # back to the list the action came from: Posture · Scans with its domain filter (view; * = all domains), else
        # filtered to this domain
        view = data.get("view") or dom
        return back(schedules_page("" if view == "*" else view), notice)

    # --- routes: named scan routes and the shared route settings (admin only; URL kept from "Scan settings") ------

    state_dir = settings.db_path.parent   # the tunnel request and status files (domin-mullvad.path watches it)
    route_page = base + "/security/scan-settings"

    def scan_settings_view(request, c, u, s, status: int = 200, error: str = "", form: dict | None = None,
                           test: tuple[bool, str] | None = None, edit: dict | None = None):
        """form: a refused shared save; edit: the route form (a refused save, or ?edit=<id>). Never a password,
        account number or key."""
        cap = proxy.host_check(c, state_dir)   # socket probes are cached: quick
        proxy.ready_made(c, cap)   # a Tor and a Mullvad route once this host supports them
        saved = proxy.get(c)
        cfg = proxy.public(saved)
        tun = mullvad.tunnel_public(mullvad.get_tunnel(c))
        if form:
            cfg.update({k: form.get(k, "") for k in (*proxy.USES, "doh") if k in form})
            tun.update(address=form.get("mullvad_address", ""), entry=form.get("mullvad_entry", ""))
        relays, _ = mullvad.load(c)
        countries = mullvad.countries(relays)
        if edit is None:
            old = proxy.find(saved, request.query_params.get("edit", ""))
            edit = proxy.public_route(old) if old else {   # a new route: the usual values prefilled
                **proxy.ROUTE_DEFAULT, "mullvad_fallback": proxy.MULLVAD_FALLBACK
                if any(cc == proxy.MULLVAD_FALLBACK for cc, _, _ in countries) else ""}
        done = proxy.tests(c)
        profiles = {p["name"]: p.get("route", "") for p in posture.profiles(c)}
        rows, warnings = [], []
        for r in cfg["routes"]:
            roles = [name for use, name in proxy.ROLES.items() if saved[use] == r["id"]]
            used_by = [n for n, rid in profiles.items() if rid == r["id"] or (not rid and saved["posture"] == r["id"])]
            row = {**r, "details": proxy.details(r), "roles": roles, "profiles": used_by, "test": done.get(r["id"]),
                   "warning": proxy.warning(r, done.get(r["id"]))}
            rows.append(row)
            if row["warning"] and (roles or used_by):
                uses = roles + [f"profile {p}" for p in used_by]
                warnings.append(f"{r['name']} is {row['warning']} but in use ({', '.join(uses)}): "
                                + ("scans on it fail until it is enabled." if not r["enabled"] else
                                   "run Test again, or pick another route there."))
        apply = cap["apply"]
        return shell(request, "scan_settings.html", u, s, status, cfg=cfg, rows=rows, edit=edit, types=proxy.TYPES,
                     kinds=proxy.KINDS, kind_choices=proxy.kinds(cap, edit.get("kind", "")), cap=cap,
                     warnings=warnings, route_names=proxy.picker_names(saved, done), error=error, test=test,
                     state=proxy.state_line(saved),
                     modes=mullvad.MODE_NAMES, countries=countries, cities=mullvad.cities(relays),
                     tun=tun, apply=apply, last=mullvad.explain(apply))

    @app.get(route_page, response_class=HTMLResponse, include_in_schema=False)
    def scan_settings_page(request: Request):   # a sync route (thread pool): host_check may wait on a socket
        with conn() as c:
            s, u, redirect = admin_only(request, c)
            if redirect:
                return redirect
            return scan_settings_view(request, c, u, s)

    @app.post(route_page + "/default", include_in_schema=False)
    async def scan_route_default(request: Request):
        """The preferred route: the default for posture scans (profiles on Default, ad-hoc fingerprints)."""
        data = await form(request)
        with conn() as c:
            s, u, redirect = admin_only(request, c, data)
            if redirect:
                return redirect
            try:
                proxy.put(c, proxy.check_shared({"posture": data.get("posture") or proxy.DIRECT}, proxy.get(c)))
            except ValueError as exc:
                return scan_settings_view(request, c, u, s, 422, str(exc))
        return back(route_page, "default-saved")

    @app.post(route_page + "/routes/{rid}/enabled", include_in_schema=False)
    async def scan_route_enabled(request: Request, rid: str):
        """Turn a route on or off; off: every scan on it fails closed with that reason."""
        data = await form(request)
        with conn() as c:
            s, u, redirect = admin_only(request, c, data)
            if redirect:
                return redirect
            if not proxy.set_enabled(c, rid, data.get("on") == "1"):
                return scan_settings_view(request, c, u, s, 404, "That route no longer exists.")
        return back(route_page, "route-saved")

    @app.post(route_page, include_in_schema=False)
    async def scan_settings_save(request: Request):
        """The shared settings: default, inventory and CVE look-up routes, DoH server, Mullvad tunnel credentials."""
        data = await form(request)
        with conn() as c:
            s, u, redirect = admin_only(request, c, data)
            if redirect:
                return redirect
            try:   # both checked before either is stored
                tunnel_cfg = mullvad.check_tunnel(data, mullvad.get_tunnel(c))
                shared = proxy.check_shared(data, proxy.get(c))
            except ValueError as exc:
                return scan_settings_view(request, c, u, s, 422, str(exc), data)
            proxy.put(c, shared)
            changed = mullvad.save_tunnel(c, tunnel_cfg)
        if changed:
            mullvad.request_apply(state_dir)
            return back(route_page, "tunnel-requested")
        return back(route_page, "saved")

    @app.post(route_page + "/routes", include_in_schema=False)
    async def scan_route_save(request: Request):
        """Add a named route (blank id) or change one."""
        data = await form(request)
        with conn() as c:
            s, u, redirect = admin_only(request, c, data)
            if redirect:
                return redirect
            try:
                proxy.save_route(c, data)
            except ValueError as exc:
                old = proxy.find(proxy.get(c), (data.get("id") or "").strip())
                edit = {**proxy.ROUTE_DEFAULT, **{k: data.get(k, "") for k in proxy.ROUTE_DEFAULT
                                                  if k not in ("password", "enabled")},
                        "enabled": data.get("enabled") == "on", "password_saved": bool(old and old.get("password"))}
                return scan_settings_view(request, c, u, s, 422, str(exc), edit=edit)
        return back(route_page, "route-saved")

    @app.post(route_page + "/routes/{rid}/delete", include_in_schema=False)
    async def scan_route_delete(request: Request, rid: str):
        data = await form(request)
        with conn() as c:
            s, u, redirect = admin_only(request, c, data)
            if redirect:
                return redirect
            if error := proxy.delete_route(c, rid):
                return scan_settings_view(request, c, u, s, 409, error)
        return back(route_page, "route-deleted")

    @app.post(route_page + "/tunnel", include_in_schema=False)
    async def scan_settings_tunnel(request: Request):
        """Ask the host to apply the saved tunnel settings again (no secrets in the request file)."""
        data = await form(request)
        with conn() as c:
            s, u, redirect = admin_only(request, c, data)
            if redirect:
                return redirect
        mullvad.request_apply(state_dir)
        return back(route_page, "tunnel-requested")

    @app.post(route_page + "/tor", include_in_schema=False)
    async def scan_settings_tor(request: Request):
        """Turn the local tor service on or off: a request file for the root unit domin-tor.path (admin only)."""
        data = await form(request)
        with conn() as c:
            s, u, redirect = admin_only(request, c, data)
            if redirect:
                return redirect
            want = data.get("tor", "")
            if want not in ("on", "off"):
                return scan_settings_view(request, c, u, s, 422, "Tor service: on or off.")
        proxy.request_tor(state_dir, want == "on")
        return back(route_page, "tor-requested")

    @app.post(route_page + "/relays", include_in_schema=False)
    async def scan_settings_relays(request: Request):
        data = await form(request)
        with conn() as c:
            s, u, redirect = admin_only(request, c, data)
            if redirect:
                return redirect
        try:
            fresh = await run_in_threadpool(mullvad.fetch, http)
        except mullvad.MullvadError as exc:
            with conn() as c:
                return scan_settings_view(request, c, u, s, 502, str(exc))
        with conn() as c:
            mullvad.store(c, fresh)
        return back(route_page, "relays")

    @app.post(route_page + "/test", include_in_schema=False)
    async def scan_settings_test(request: Request):
        """Handshake with one saved route's proxy from the web process (Mullvad: the in-tunnel SOCKS5); no traffic
        to any target."""
        data = await form(request)
        with conn() as c:
            s, u, redirect = admin_only(request, c, data)
            if redirect:
                return redirect
            r = proxy.find(proxy.get(c), (data.get("route") or "").strip())
        if not r:
            result = (False, "Pick a saved route to test (Direct has nothing to test).")
        elif r["kind"] == "mullvad":
            ok, msg = await run_in_threadpool(proxy.tunnel_state)
            result = (ok, f"{r['name']}: {msg}")
        else:
            try:
                result = (True, f"{r['name']}: " + await run_in_threadpool(proxy.handshake, proxy.greet_target(r)))
            except proxy.ProxyError as exc:
                result = (False, f"{r['name']}: {exc}")
        with conn() as c:
            if r:   # the row's Verified column
                proxy.record_test(c, r["id"], result[0], result[1].split(": ", 1)[1])
            return scan_settings_view(request, c, u, s, test=result)

    @app.post(base + "/security/scan", include_in_schema=False)
    async def security_scan(request: Request):
        data = await form(request)
        host_params = None
        with conn() as c:
            s, u = current(request, c, data)
            if not u:
                return back()
            routes = proxy.get(c)
            grants = request.state.scope
            if not grants.manages_any:
                return lookup_view(request, u, s, security_ctx(
                    403, error="Running a look-up needs domain admin rights on a domain."))
            if data.get("kind") == "host":
                tgt = (data.get("target") or "").strip()
                ports = (data.get("ports") or "").strip() or fingerprint.DEFAULT_PORTS
                if not fingerprint.valid_target(tgt):
                    return lookup_view(request, u, s, security_ctx(
                        422, form=data, error="Enter one host name or IPv4 address to fingerprint."))
                if not grants.everything and (_is_ip(tgt) or not grants.manages(tgt.lower())):
                    return lookup_view(request, u, s, security_ctx(
                        403, form=data, error="Fingerprint a host name under a domain you are domain admin of "
                                              "(addresses: admins only)."))
                if not fingerprint.valid_ports(ports):
                    return lookup_view(request, u, s, security_ctx(
                        422, form=data, error="Ports: digits, commas and hyphens only (e.g. 22,80,443 or 1-1024)."))
                name, ips = fingerprint.resolve(tgt)
                if not ips:
                    return lookup_view(request, u, s, security_ctx(
                        422, form=data, error=f"Could not resolve {tgt}."))
                if bad := netscope.refused(ips, netscope.checker(c, settings)):   # every address the name has
                    return lookup_view(request, u, s, security_ctx(
                        403, form=data, error=f"{name} ({', '.join(bad)}) is not a scannable address on this install "
                                              "(loopback, private, link-local and other non-public ranges)."))
                if not all(users.posture_ip_in_scope(c, ip) for ip in ips):
                    return lookup_view(request, u, s, security_ctx(
                        403, form=data,
                        error=f"{name} ({', '.join(ips)}) is outside the posture scope. Add it under Settings first."))
                host_params = (ips[0], name, ports)
            else:
                try:
                    target = cve.parse_target(data)
                except ValueError as exc:
                    return lookup_view(request, u, s, security_ctx(422, form=data, error=str(exc)))
        def pick_hops(ip: str) -> tuple[dict | None, dict | None]:   # in the thread pool: may fetch relay lists
            """(scan hop, CVE look-up hop) for an ad-hoc fingerprint: the default route."""
            with conn() as c2:
                r = proxy.pick(routes)
                hop = proxy.hop(c2, r, ip, "", http)
                return hop, proxy.cve_hop(c2, routes, r, hop, http)

        def lookup_hop() -> dict | None:
            with conn() as c2:
                return proxy.cve_hop(c2, routes, client=http)

        if host_params is not None:
            ip0, name, ports = host_params
            try:
                hop, cve_via = await run_in_threadpool(pick_hops, ip0)
            except proxy.ProxyError as exc:   # fail closed: no direct scan instead
                scan = {"target": name, "ip": ip0, "services": [], "note": "", "error": f"route: {exc}",
                        "params": f"via {proxy.label(routes) or 'a deleted route'}"}
                return lookup_view(request, u, s, security_ctx(host_result=scan, form=data))
            with proxy.cve_client(cve_via, http) as lookups:
                scan = await run_in_threadpool(
                    fingerprint.scan, ip0, cve_db=cve_db, client=lookups, api_key=settings.nvd_api_key,
                    ports=ports, display=name, via=hop)
            return lookup_view(request, u, s, security_ctx(host_result=scan, form=data))
        cve_via = await run_in_threadpool(lookup_hop)   # route down: local database only (proxy.NO_LOOKUPS)
        with proxy.cve_client(cve_via, http) as lookups:
            result = await run_in_threadpool(cve.lookup, cve_db, target, lookups, settings.nvd_api_key)
        result["label"] = cve.target_label(target)
        return lookup_view(request, u, s, security_ctx(result=result, form=data))

    # --- tuning and jobs (admins) ----------------------------------------------------------------------

    @app.post(base + "/tune", include_in_schema=False)
    async def admin_tune(request: Request):
        data = await form(request)
        with conn() as c:
            s, u = current(request, c, data)
            if not u or u["role"] != "admin":
                return back()
            try:
                admin.save_tuning(c, data)
            except ValueError as exc:
                return dashboard(request, c, u, s, error=str(exc), status=422)
        return back(base, "tuned")

    @app.post(base + "/jobs/{job_id}/{action}", include_in_schema=False)
    async def admin_job(request: Request, job_id: PathId, action: str):
        data = await form(request)
        with conn() as c:
            s, u = current(request, c, data)
            if not u or u["role"] != "admin":
                return back()
            if action == "cancel":
                return back(base, "cancelled" if jobs.cancel(c, job_id) else "gone")
            if action == "retry":
                job = jobs.get(c, job_id)
                if not job:
                    raise HTTPException(404, "No such job")
                jobs.enqueue(c, job["domain"], client="admin")
                return back(base, "retried")
        raise HTTPException(404, "Unknown action")
