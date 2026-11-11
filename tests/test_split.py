"""DNS inventory and security posture are separate areas: the inventory pages (/, /all, /d/..., /tools) show DNS-scan
data only and link only to inventory pages; Posture is reached through its top-bar entry. Posture pages show posture
data and link to the inventory only through an explicit "View DNS records" action."""
import json
import re

from test_posture import DOM, app_client, nmap, run_queue, settings, sign_in  # noqa: F401 (fixtures)

from domin import db, jobs
from domin.web import POSTURE_KEYS

POSTURE = "/admin/security"
LINK = re.compile(r'(?:href|action|data-[a-z-]+)="([^"]*)"')
INVENTORY = re.compile(r"^/(?:$|[?#]|d/|all|search|tools|scans/)")


def main(html: str) -> str:
    """The page body without the top bar (the nav keeps its Posture entry for users with the right)."""
    return html.split('<main class="wrap">', 1)[1].split("</main>", 1)[0]


def seeded(settings, h) -> dict:  # noqa: F811
    """A domain with two DNS scans, a finished posture scan, an nmap discovery result and a queued DNS job."""
    csrf = sign_in(h, "adm")
    assert h.post(POSTURE + "/posture", data={"csrf": csrf, "domain": DOM}).status_code in (200, 303)
    assert run_queue(settings)
    with db.connect(settings.db_path) as c:
        db.save_scan(c, DOM, db.now(), "scan", [{"host": "www.corp.example", "ip": "172.20.4.50"}])
        a, b = (r[0] for r in c.execute("SELECT id FROM scans ORDER BY id"))
        db.save_discovery(c, b, "default", "nmap -sn",
                          [{"ip": "172.20.4.77", "names": [], "ports": ["8443/tcp"], "reason": "syn-ack"}])
        job = jobs.enqueue(c, DOM, client="admin", discovery="default")
    return {"a": a, "b": b, "job": job["id"]}


def inventory_pages(ids: dict) -> list[str]:
    return ["/", "/all", "/all?q=corp", f"/d/{DOM}", f"/d/{DOM}?scan={ids['a']}",
            f"/d/{DOM}/compare?a={ids['a']}&b={ids['b']}", f"/tools?domain={DOM}"]


def test_inventory_pages_have_no_posture_links_or_data(settings, nmap):  # noqa: F811
    with app_client(settings) as h:
        ids = seeded(settings, h)
        for url in inventory_pages(ids):
            r = h.get(url)
            assert r.status_code == 200, url
            body = main(r.text)
            links = LINK.findall(body)
            assert not [x for x in links if x.startswith(POSTURE)], url
            # the rest: inventory pages, plus the tag and viewer forms (not posture) and the drill data
            assert not [x for x in links if x.startswith("/") and not INVENTORY.match(x)
                        and not x.startswith(("/admin/tags", "/admin/domains/", "/data/drill.json"))], url
            for posture_bit in ('id="posture', "posture-data", "CVE-", "8443/tcp", "nmap discovery",
                                "Scheduled rescans", "Scan with nmap"):
                assert posture_bit not in body, (url, posture_bit)
            # the top bar: the explicit Posture entry only
            head = r.text.split('<main class="wrap">', 1)[0]
            assert re.findall(r'href="(/admin/security[^"]*)"', head) == [POSTURE], url
    with app_client(settings) as h:   # a visitor without a session: no way into Posture at all
        assert POSTURE not in h.get("/").text and POSTURE not in h.get(f"/d/{DOM}").text


def test_activity_panel_lists_dns_jobs_only(settings, nmap):  # noqa: F811
    with app_client(settings) as h:
        seeded(settings, h)
        with db.connect(settings.db_path) as c:
            dns_jobs = c.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
            assert c.execute("SELECT COUNT(*) FROM posture_scans").fetchone()[0]   # posture work exists
        panel = h.get("/").text.split('<ul class="jobs">', 1)[1].split("</ul>", 1)[0]
    items = re.findall(r"<li>.*?</li>", panel, re.S)
    assert len(items) == dns_jobs == 1
    assert all(re.findall(r'href="([^"]*)"', i) == [f"/d/{DOM}"] for i in items)
    assert "172.20.4." not in panel and "nmap" not in panel   # no posture targets, no discovery profile


def test_inventory_api_returns_no_posture_fields(settings, nmap):  # noqa: F811
    with app_client(settings) as h:
        ids = seeded(settings, h)
        rows = [h.get(f"/api/jobs/{ids['job']}").json(), h.get(f"/api/scans/{ids['b']}").json()["scan"],
                *h.get(f"/api/domains/{DOM}/history").json()]
        charts = json.loads(re.search(r'id="page-data">(.*?)</script>', h.get(f"/d/{DOM}").text).group(1))
        rows += charts["history"]
        drill = h.get("/data/drill.json?scope=latest").text
    assert rows and not [k for r in rows for k in r if k in POSTURE_KEYS]
    assert "8443" not in drill and "CVE-" not in drill


def test_posture_pages_link_to_the_inventory_only_through_view_dns_records(settings, nmap):  # noqa: F811
    with app_client(settings) as h:
        ids = seeded(settings, h)
        for url in (POSTURE, f"{POSTURE}?domain={DOM}", f"{POSTURE}/analysis", f"{POSTURE}/analysis?domain={DOM}",
                    f"{POSTURE}/scans", f"{POSTURE}/scans?domain={DOM}"):
            body = main(h.get(url).text)
            inv = [x for x in LINK.findall(body) if INVENTORY.match(x)]
            assert set(inv) <= {f"/d/{DOM}"} | {f"/d/{DOM}?scan={i}" for i in ids.values()}, (url, inv)
            assert 'id="pc-footprint"' not in body   # the inventory footprint chart is not on Posture
            if "domain=" in url:
                assert f'<a class="btn" href="/d/{DOM}">View DNS records</a>' in body, url
        scans = main(h.get(f"{POSTURE}/scans?domain={DOM}").text)   # nmap discovery moved here from the domain page
        disc = scans.split('id="discovery"', 1)[1].split("</section>", 1)[0]
        assert "172.20.4.77" in disc and "8443/tcp" in disc and "Scan with nmap" in disc
