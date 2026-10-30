"""Web app: server-rendered pages (Jinja2) with chart data as JSON blocks, plus a small JSON API.

Run: uvicorn --factory domin.web:create_app --port 8002 (behind nginx; X-Real-IP is trusted from localhost only)."""
from __future__ import annotations

import csv
import io
from functools import lru_cache
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from . import db, jobs, tools
from .config import Settings
from .validate import normalize_domain

HERE = Path(__file__).parent
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
CHURN_SCANS = 40   # host churn chart: the newest N scans of a domain


class ScanIn(BaseModel):
    domain: str


def create_app(settings: Settings | None = None, http: httpx.Client | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    db.init(settings.db_path)
    app = FastAPI(title="domin", docs_url=None, redoc_url=None, openapi_url=None)
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    templates = Jinja2Templates(directory=HERE / "templates")
    client = http or httpx.Client(headers={"User-Agent": "domin/2 (domain inventory)"}, follow_redirects=True)

    def conn():
        return db.connect(settings.db_path)

    def client_ip(request: Request) -> str:
        peer = request.client.host if request.client else ""
        if peer in ("127.0.0.1", "::1"):
            return request.headers.get("x-real-ip", peer)
        return peer

    def page(request: Request, name: str, status: int = 200, **ctx) -> HTMLResponse:
        return templates.TemplateResponse(request, name, ctx, status_code=status)

    def domain_or_404(c, name: str) -> dict:
        d = db.domain(c, name)
        if not d:
            raise HTTPException(404, f"{name} has not been scanned")
        return d

    @app.middleware("http")
    async def headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers.update({"Content-Security-Policy": CSP, "X-Content-Type-Options": "nosniff",
                             "Referrer-Policy": "same-origin", "X-Frame-Options": "DENY"})
        if request.url.path.startswith("/static/"):
            resp.headers["Cache-Control"] = "no-cache"   # revalidate (ETag) so a deploy shows at once
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
                    "asns": db.top_latest(c, "asn")}

    def data_version(c) -> str:
        return str(c.execute("SELECT COALESCE(MAX(id), 0) FROM scans").fetchone()[0])

    # --- pages ---------------------------------------------------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    def overview(request: Request):
        with conn() as c:
            version = data_version(c)
            domains = db.domains_overview(c)
            recent = jobs.recent(c, 8)
        return page(request, "overview.html", data=overview_data(version), domains=domains, recent=recent)

    @app.get("/d/{name}", response_class=HTMLResponse)
    def domain_page(request: Request, name: str, scan: int | None = None):
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
        return [{"id": b["id"], "started": b["started"], "added": len(sets[b["id"]] - sets[a["id"]]),
                 "removed": len(sets[a["id"]] - sets[b["id"]])} for a, b in zip(scans, scans[1:], strict=False)]

    @app.get("/d/{name}/compare", response_class=HTMLResponse)
    def compare(request: Request, name: str, a: int, b: int):
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
        name = normalize_domain(body.domain)
        if not name:
            raise HTTPException(422, "Not a valid domain name")
        who = client_ip(request)
        with conn() as c:
            if jobs.scans_by_client(c, who) >= settings.scans_per_hour:
                raise HTTPException(429, f"At most {settings.scans_per_hour} scans per hour")
            return jobs.enqueue(c, name, client=who)

    @app.get("/api/jobs/{job_id}")
    def api_job(job_id: int):
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
    def api_scan_records(scan_id: int):
        with conn() as c:
            s = db.scan(c, scan_id)
            if not s:
                raise HTTPException(404, "No such scan")
            return {"scan": s, "records": db.records(c, scan_id)}

    @app.get("/scans/{scan_id}.csv")
    def scan_csv(scan_id: int):
        with conn() as c:
            s = db.scan(c, scan_id)
            if not s:
                raise HTTPException(404, "No such scan")
            rows = db.records(c, scan_id)
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=list(db.RECORD_FIELDS))
        w.writeheader()
        w.writerows(rows)
        fname = f"{s['domain']}_{s['started'][:10]}.csv"
        return Response(buf.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="{fname}"'})

    @app.get("/api/rdap/{name}")
    def api_rdap(name: str):
        d = normalize_domain(name)
        if not d:
            raise HTTPException(422, "Not a valid domain name")
        try:
            return tools.rdap(d, client)
        except httpx.HTTPError as exc:
            raise HTTPException(502, f"RDAP lookup failed: {type(exc).__name__}") from None

    @app.get("/api/email/{name}")
    def api_email(name: str):
        d = normalize_domain(name)
        if not d:
            raise HTTPException(422, "Not a valid domain name")
        return tools.email_security(d)

    return app
