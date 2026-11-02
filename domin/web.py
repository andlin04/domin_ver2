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
import threading
import time
from collections import defaultdict, deque
from functools import lru_cache
from pathlib import Path
from typing import Annotated
from urllib.parse import parse_qs, urlsplit

import httpx
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi import Path as PathParam
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from . import admin, db, jobs, tools
from .config import Settings
from .validate import normalize_domain

HERE = Path(__file__).parent
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
CHURN_SCANS = 40   # host churn chart: the newest N scans of a domain
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


def create_app(settings: Settings | None = None, http: httpx.Client | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
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

    def admin_allowed(request: Request) -> bool:
        try:
            ip = ipaddress.ip_address(peer_ip(request))
        except ValueError:
            return False
        return any(ip in n for n in admin_nets)

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

    def page(request: Request, name: str, status: int = 200, **ctx) -> HTMLResponse:
        return templates.TemplateResponse(request, name, {"show_admin": admin_allowed(request), **ctx},
                                          status_code=status)

    def domain_or_404(c, name: str) -> dict:
        d = db.domain(c, name)
        if not d:
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

    @app.middleware("http")
    async def headers(request: Request, call_next):
        path = request.url.path
        if (path == ADMIN or path.startswith(ADMIN + "/")) and not admin_allowed(request):
            resp = JSONResponse({"detail": "Not Found"}, status_code=404)   # same answer as a path that doesn't exist
        else:
            resp = await call_next(request)
        resp.headers.update({"Content-Security-Policy": CSP, "X-Content-Type-Options": "nosniff",
                             "Referrer-Policy": "same-origin", "X-Frame-Options": "DENY"})
        if request.url.path.startswith("/static/"):
            resp.headers["Cache-Control"] = "no-cache"   # revalidate (ETag) so a deploy shows at once
        kind = visit_kind(request, resp.status_code)
        if kind and kind[0]:
            try:   # statistics never break a page
                await run_in_threadpool(record_visit, request, *kind, getattr(request.state, "domain", None))
            except Exception:
                log.exception("visit not recorded")
        return resp

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"error": exc.detail}, status_code=exc.status_code)
        return page(request, "error.html", exc.status_code, message=exc.detail, code=exc.status_code)

    @lru_cache(maxsize=4)
    def overview_data(version: str) -> dict:
        with conn() as c:
            return {"totals": db.totals(c), "per_day": db.scans_per_day(c),
                    "countries": db.top_latest(c, "country"), "netnames": db.top_latest(c, "netname"),
                    "asns": db.top_latest(c, "asn"),
                    "eu": db.eu_per_day(c)}

    def data_version(c) -> str:
        return str(c.execute("SELECT COALESCE(MAX(id), 0) FROM scans").fetchone()[0])

    # --- pages ---------------------------------------------------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    def overview(request: Request):
        with conn() as c:
            version = data_version(c)
            domains = db.domains_overview(c)
            recent = jobs.recent(c, 8)
            src = drill_src(c, False)
        return page(request, "overview.html", data=overview_data(version), domains=domains, recent=recent,
                    drill_rows=drill_preview(version), fields=SEARCH_LABELS, drill_src=src)

    @lru_cache(maxsize=2)
    def drill_preview(version: str) -> list[dict]:
        """The first records for the overview's Drilldown tab (latest scans, no filter)."""
        with conn() as c:
            return db.search(c, limit=SEARCH_PAGE)[0]

    @app.get("/d/{name}", response_class=HTMLResponse)
    def domain_page(request: Request, name: str, scan: QueryId | None = None):
        with conn() as c:
            d = domain_or_404(c, name)
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
                  "asns": db.breakdown(rows, "asn", 10)}
        return page(request, "domain.html", domain=d, scans=done, current=current, previous=previous,
                    rows=rows, change=change, charts=charts, open_job=open_job["id"] if open_job else None)

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
            d = domain_or_404(c, name)
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
    def summary(version: str, q: str, field: str, history: bool, cols: tuple) -> dict:
        with conn() as c:
            return db.search_summary(c, q, field, history, dict(cols))

    @lru_cache(maxsize=16)
    def history_page(hour: str, offset: int) -> tuple[list[dict], int]:
        with conn() as c:
            return db.search(c, history=True, limit=SEARCH_PAGE, offset=offset)

    # The Drilldown filters in the browser: it fetches the whole dataset once (gzip'd JSON, cached by the browser
    # until the next scan, or the next hour for the history), so typing in a filter costs the server nothing.
    # The server-side search above stays as the fallback (no JavaScript, data not loaded) and for the CSV.
    drill_cache: dict[bool, tuple[str, bytes]] = {}
    drill_locks = {False: threading.Lock(), True: threading.Lock()}

    def drill_key(c, history: bool) -> str:
        """Changes with the data (latest scan, or the hour) and with DRILL_FORMAT, so browsers never reuse a
        cached copy in an older layout."""
        return f"{DRILL_FORMAT}-{db.now()[:13] if history else data_version(c)}"

    def drill_data(key: str, history: bool) -> bytes:
        with drill_locks[history]:   # one build at a time; the others wait for it
            if drill_cache.get(history, ("",))[0] != key:
                with conn() as c:
                    data = db.drill_columns(c, history)
                drill_cache[history] = key, gzip.compress(json.dumps(data, separators=(",", ":")).encode(), 6)
            return drill_cache[history][1]

    def drill_src(c, history: bool) -> str:
        return f"/data/drill.json?scope={'all' if history else 'latest'}&v={drill_key(c, history)}"

    @app.get("/data/drill.json")
    def drill_json(scope: str = "latest", v: str = ""):
        history = scope == "all"
        with conn() as c:
            key = drill_key(c, history)
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

    @app.get("/all", response_class=HTMLResponse)
    @app.get("/search", response_class=HTMLResponse, include_in_schema=False)   # the page's first address
    def all_domains(request: Request, q: str = "", field: str = "", scope: str = "latest",
                    page_no: Annotated[int, Query(alias="page", ge=1, le=100_000)] = 1):
        args = search_args(request, q, field, scope)
        offset = (page_no - 1) * SEARCH_PAGE
        unfiltered_history = args["history"] and not args["q"] and not args["columns"]
        with conn() as c:
            version = data_version(c)
            src = drill_src(c, args["history"])
            if not unfiltered_history:
                rows, total = db.search(c, **args, limit=SEARCH_PAGE, offset=offset)
        if unfiltered_history:
            rows, total = history_page(db.now()[:13], offset)
            stats = summary(db.now()[:13], "", "", True, ())
        else:
            stats = summary(version, args["q"], args["field"], args["history"], tuple(sorted(args["columns"].items())))
        pages = max(1, -(-total // SEARCH_PAGE))
        return page(request, "search.html", rows=rows, total=total, page_no=page_no, pages=pages, stats=stats,
                    hourly=unfiltered_history,
                    q=args["q"], field=args["field"], scope="all" if args["history"] else "latest",
                    cols=args["columns"], fields=SEARCH_LABELS, drill_src=src)

    @app.get("/search.csv")
    def search_csv(request: Request, q: str = "", field: str = "", scope: str = "latest"):
        args = search_args(request, q, field, scope)
        with conn() as c:
            rows, _ = db.search(c, **args, limit=SEARCH_CSV_MAX)
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
        name = normalize_domain(body.domain)
        if not name:
            raise HTTPException(422, "Not a valid domain name")
        request.state.domain = name
        with conn() as c:
            s = admin.effective(settings, c)
            who = admin.client_key(c, client_ip(request))
            last = c.execute("SELECT MAX(s.started) FROM scans s JOIN domains d ON d.id = s.domain_id WHERE d.name = ?",
                             (name,)).fetchone()[0]
            if s.once_per_day and last and last[:10] == db.now()[:10]:
                raise HTTPException(429, f"{name} was already scanned today; the next scan can run tomorrow")
            if jobs.scans_by_client(c, who) >= s.scans_per_hour:
                raise HTTPException(429, f"At most {s.scans_per_hour} scans per hour")
            if jobs.scans_by_client(c, who, minutes=24 * 60) >= s.scans_per_day:
                raise HTTPException(429, f"At most {s.scans_per_day} scans per day")
            if jobs.queued(c) >= s.queue_max:
                raise HTTPException(503, "The scan queue is full; try again later")
            return jobs.enqueue(c, name, client=who)

    @app.get("/api/jobs/{job_id}")
    def api_job(job_id: PathId):
        with conn() as c:
            job = jobs.get(c, job_id)
        if not job:
            raise HTTPException(404, "No such job")
        return job

    @app.get("/api/domains")
    def api_domains(q: str = ""):
        with conn() as c:
            return db.domains_overview(c, q.strip().lower())

    @app.get("/api/domains/{name}/history")
    def api_history(name: str):
        with conn() as c:
            domain_or_404(c, name)
            return db.history(c, name)

    @app.get("/api/scans/{scan_id}")
    def api_scan_records(scan_id: PathId):
        with conn() as c:
            s = db.scan(c, scan_id)
            if not s:
                raise HTTPException(404, "No such scan")
            return {"scan": s, "records": db.records(c, scan_id)}

    @app.get("/scans/{scan_id}.csv")
    def scan_csv(scan_id: PathId, request: Request):
        with conn() as c:
            s = db.scan(c, scan_id)
            if not s:
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

    add_admin(app, settings, conn, page, client_ip)
    return app


NOTICES = {"tuned": "Settings saved; they apply at once.", "cancelled": "Job cancelled.", "retried": "Job queued.",
           "gone": "That job had already finished."}


def add_admin(app: FastAPI, settings: Settings, conn, page, client_ip) -> None:
    """The admin page at /admin, for DOMIN_ADMIN_IPS only (anyone else gets the same 404 as an unknown path): one
    password (python -m domin admin-password), a session cookie, a CSRF token per session on every form."""
    base = ADMIN
    private = {"Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow"}

    async def form(request: Request) -> dict[str, str]:
        body = await request.body()
        if len(body) > 10_000:
            raise HTTPException(413, "Form too large")
        return {k: v[0] for k, v in parse_qs(body.decode("utf-8", "replace")).items()}

    def signed_in(request: Request, c, data: dict[str, str] | None = None) -> dict | None:
        """The session, or None; with form data, the form's CSRF token must match the session's."""
        s = admin.session(c, request.cookies.get(COOKIE))
        if s and data is not None and not hmac.compare_digest(data.get("csrf", ""), s["csrf"]):
            raise HTTPException(403, "The form expired; reload the page and try again")
        return s

    def back(notice: str = "") -> RedirectResponse:
        return RedirectResponse(f"{base}?ok={notice}" if notice else base, status_code=303, headers=private)

    def dashboard(request: Request, c, s: dict, error: str = "", status: int = 200) -> HTMLResponse:
        live = admin.effective(settings, c)
        resp = page(request, "admin.html", status, base=base, csrf=s["csrf"], stats=admin.report(c),
                    jobs=jobs.admin_list(c), tunable=[(k, *v, getattr(live, k)) for k, v in admin.TUNABLE.items()],
                    notice=NOTICES.get(request.query_params.get("ok", ""), ""), error=error)
        resp.headers.update(private)
        return resp

    @app.get(base, response_class=HTMLResponse, include_in_schema=False)
    def admin_page(request: Request):
        with conn() as c:
            s = signed_in(request, c)
            if s:
                return dashboard(request, c, s)
            has_password = admin.kv_get(c, "admin_password") is not None
        resp = page(request, "login.html", base=base, has_password=has_password, error="")
        resp.headers.update(private)
        return resp

    @app.post(base + "/login", include_in_schema=False)
    async def admin_login(request: Request):
        data = await form(request)
        with conn() as c:
            who = admin.client_key(c, client_ip(request))
            if admin.login_blocked(c, who):
                error, status = "Too many failed sign-ins; wait 15 minutes.", 429
            elif admin.check_password(c, data.get("password", "")):
                resp = back()
                resp.set_cookie(COOKIE, admin.new_session(c), max_age=admin.SESSION_HOURS * 3600, path="/",
                                secure=True, httponly=True, samesite="strict")
                return resp
            else:
                admin.login_failed(c, who)
                error, status = "Wrong password.", 401
            has_password = admin.kv_get(c, "admin_password") is not None
        resp = page(request, "login.html", status, base=base, has_password=has_password, error=error)
        resp.headers.update(private)
        return resp

    @app.post(base + "/logout", include_in_schema=False)
    async def admin_logout(request: Request):
        data = await form(request)
        with conn() as c:
            if signed_in(request, c, data):
                admin.end_session(c, request.cookies.get(COOKIE))
        resp = back()
        resp.delete_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="strict")
        return resp

    @app.post(base + "/tune", include_in_schema=False)
    async def admin_tune(request: Request):
        data = await form(request)
        with conn() as c:
            s = signed_in(request, c, data)
            if not s:
                return back()
            try:
                admin.save_tuning(c, data)
            except ValueError as exc:
                return dashboard(request, c, s, error=str(exc), status=422)
        return back("tuned")

    @app.post(base + "/jobs/{job_id}/{action}", include_in_schema=False)
    async def admin_job(request: Request, job_id: PathId, action: str):
        data = await form(request)
        with conn() as c:
            if not signed_in(request, c, data):
                return back()
            if action == "cancel":
                return back("cancelled" if jobs.cancel(c, job_id) else "gone")
            if action == "retry":
                job = jobs.get(c, job_id)
                if not job:
                    raise HTTPException(404, "No such job")
                jobs.enqueue(c, job["domain"], client="admin")
                return back("retried")
        raise HTTPException(404, "Unknown action")
