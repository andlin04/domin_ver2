"""Domain info card (domin.domaininfo): the security.txt parser, the RDAP summary and the Analysis card endpoint.
Every look-up answers from a fake transport; nothing reaches the network."""
from dataclasses import replace

import httpx
from fastapi.testclient import TestClient
from test_posture import DOM, add_done, sign_in
from test_posture import settings as settings  # noqa: F401  (the fixture)

from domin import db, domaininfo
from domin.web import create_app

NOW = 1_800_000_000.0   # 2027-01-15

PLAIN = """# a comment
Contact: mailto:security@corp.example
contact: https://corp.example/report
Contact: tel:+1-201-555-0123
Expires: 2099-12-31T23:59:59.000Z
Expires: 2000-01-01T00:00:00Z
Policy: https://corp.example/policy
Encryption: https://corp.example/pgp-key.txt
Acknowledgments: https://corp.example/thanks
Preferred-Languages: en, sv
Canonical: https://corp.example/.well-known/security.txt
Hiring: https://corp.example/jobs
X-Unknown: ignored
Policy without a colon
"""

SIGNED = """-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Contact: mailto:security@corp.example
- Expires: 2026-01-01T00:00:00+01:00
-----BEGIN PGP SIGNATURE-----

iQIzBAEBCgAdFiEE
-----END PGP SIGNATURE-----
"""

RDAP = {"ldhName": "CORP.EXAMPLE", "status": ["client transfer prohibited"],
        "events": [{"eventAction": "registration", "eventDate": "2001-02-03T00:00:00Z"},
                   {"eventAction": "expiration", "eventDate": "2027-01-30T00:00:00Z"}],
        "nameservers": [{"ldhName": "NS1.CORP.EXAMPLE"}, {"ldhName": "ns2.corp.example"}],
        "secureDNS": {"delegationSigned": True},
        "entities": [
            {"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar AB"]]],
             "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [
                 ["email", {}, "text", "abuse@registrar.example"], ["tel", {"type": "voice"}, "uri", "tel:+46.80000"]]]}]},
            {"roles": ["registrant"], "vcardArray": ["vcard", [
                ["fn", {}, "text", "REDACTED FOR PRIVACY"],
                ["adr", {"cc": "SE"}, "text", ["", "", "", "", "", "", ""]]]]}]}


def test_parser_reads_fields_and_repeated_contacts():
    got = domaininfo.parse_security_txt(PLAIN)
    f = got["fields"]
    assert f["Contact"] == ["mailto:security@corp.example", "https://corp.example/report", "tel:+1-201-555-0123"]
    assert f["Expires"] == ["2099-12-31T23:59:59.000Z"]   # once; the second line is ignored
    assert f["Policy"] == ["https://corp.example/policy"] and f["Preferred-Languages"] == ["en, sv"]
    assert {"Encryption", "Acknowledgments", "Canonical", "Hiring"} <= set(f) and "X-Unknown" not in f
    assert got["valid"] and not got["signed"] and got["expires_ts"] > NOW


def test_parser_unwraps_a_signed_message_and_flags_expired():
    got = domaininfo.parse_security_txt(SIGNED)
    assert got["signed"] and got["valid"]
    assert got["fields"] == {"Contact": ["mailto:security@corp.example"], "Expires": ["2026-01-01T00:00:00+01:00"]}
    assert domaininfo.view({"sectxt": got, "at": NOW}, now=NOW)["sectxt"]["expired"]
    assert not domaininfo.view({"sectxt": domaininfo.parse_security_txt(PLAIN), "at": NOW}, now=NOW)["sectxt"]["expired"]


def test_parser_rejects_garbage():
    for text in ("", "<html><body>Not found</body></html>", "\x00\x01binary", "Expires: tomorrow"):
        got = domaininfo.parse_security_txt(text)
        assert not got["valid"] and got["expires_ts"] is None


def transport(calls: list, sectxt=PLAIN, kind="text/plain; charset=utf-8", rdap_status=200):
    def handle(req: httpx.Request) -> httpx.Response:
        calls.append(str(req.url))
        if req.url.host == "rdap.org":
            return httpx.Response(rdap_status, json=RDAP)
        if req.url.path == "/.well-known/security.txt":
            return httpx.Response(404)
        if req.url.path == "/security.txt" and sectxt is not None:
            return httpx.Response(200, text=sectxt, headers={"content-type": kind})
        return httpx.Response(404)
    return httpx.MockTransport(handle)


def test_fetch_falls_back_to_the_top_level_and_needs_text_plain():
    calls = []
    with httpx.Client(transport=transport(calls)) as c:
        got = domaininfo.fetch_security_txt(DOM, c)
    assert got["found"] and got["url"] == f"https://{DOM}/security.txt"
    assert calls == [f"https://{DOM}/.well-known/security.txt", f"https://{DOM}/security.txt"]
    with httpx.Client(transport=transport([], kind="text/html")) as c:
        got = domaininfo.fetch_security_txt(DOM, c)
    assert not got["found"] and "not text/plain (text/html)" in got["error"]


def test_fetch_caps_the_size():
    with httpx.Client(transport=transport([], sectxt="Contact: x" + "#" * 70_000)) as c:
        got = domaininfo.fetch_security_txt(DOM, c)
    assert not got["found"] and "larger than 64 KB" in got["error"]


def test_registration_summary_redacts_and_finds_the_abuse_contact():
    with httpx.Client(transport=transport([])) as c:
        reg = domaininfo.registration(domaininfo.tools.rdap(DOM, c))
    assert reg["registrar"] == "Example Registrar AB" and reg["owner"] == "" and reg["country"] == "SE"
    assert (reg["abuse_email"], reg["abuse_tel"]) == ("abuse@registrar.example", "+46.80000")
    assert reg["nameservers"] == ["ns1.corp.example", "ns2.corp.example"] and reg["dnssec"]
    shown = domaininfo.view({"rdap": reg, "at": NOW}, now=NOW)["rdap"]
    assert shown["expires_days"] == 14 and shown["expires_soon"]


# ---- endpoint ----

def client_for(settings, calls, **kw):
    return TestClient(create_app(settings, http=httpx.Client(transport=transport(calls, **kw))),
                      base_url="https://testserver", client=("127.0.0.1", 50000))


URL = f"/admin/security/domain-card?domain={DOM}"


def test_card_needs_sign_in_and_a_known_domain(settings):
    with client_for(settings, []) as h:
        assert h.get(URL).status_code == 401
        sign_in(h, "ana")
        assert h.get("/admin/security/domain-card?domain=other.example").status_code == 404


def test_card_shows_the_lookups_and_stores_them_for_a_day(settings):
    calls = []
    with client_for(settings, calls, sectxt=PLAIN.replace(
            "Hiring: https://corp.example/jobs", 'Hiring: javascript:alert(1)\nCanonical: https://x.example/"<b>')) as h:
        sign_in(h, "ana")
        r = h.get(URL)
        assert r.status_code == 200
        page = r.text
        assert "Example Registrar AB" in page and "abuse@registrar.example" in page and "redacted" in page
        assert "ns1.corp.example" in page and "client transfer prohibited" in page
        assert "Hosts</dt><dd>4 with an address" in page
        assert ('<a href="https://corp.example/policy" rel="noopener noreferrer" target="_blank">' in page)
        assert "mailto:security@corp.example" in page and 'href="mailto:' not in page   # only http(s) are links
        assert 'href="javascript:' not in page and "javascript:alert(1)" in page
        assert "<b>" not in page and "&#34;&lt;b&gt;" in page   # escaped
        assert "PGP-signed</dt><dd>no" in page and "refresh=1" in page
        n = len(calls)
        assert "stored result" in h.get(URL).text and len(calls) == n            # cache hit: no look-ups
        with db.connect(settings.db_path) as c:   # a day-old result is fetched again
            c.execute("UPDATE kv SET value = json_set(value, '$.at', 1) WHERE key = ?", (domaininfo.KEY + DOM,))
        assert "stored result" not in h.get(URL).text and len(calls) > n
        n = len(calls)
        assert "stored result" in h.get(URL + "&refresh=1").text and len(calls) == n   # refresh within a minute
        with db.connect(settings.db_path) as c:
            c.execute("UPDATE kv SET value = json_set(value, '$.at', ?) WHERE key = ?",
                      (domaininfo.time.time() - 120, domaininfo.KEY + DOM))
        assert "stored result" not in h.get(URL + "&refresh=1").text and len(calls) > n   # refresh bypasses


def test_card_counts_the_domains_posture_results(settings):
    with db.connect(settings.db_path) as c:
        add_done(c, "172.20.4.50", "2026-11-01T10:00:00", [("CVE-2099-0001", "critical"), ("CVE-2099-0002", "high")])
    with client_for(settings, []) as h:
        sign_in(h, "ana")
        r = h.get(URL)
    assert r.status_code == 200
    assert "Open CVEs</dt><dd>2" in r.text and "1 critical" in r.text and "1 address(es) scanned" in r.text


def test_card_on_a_failed_lookup_shows_the_reason_and_stores_nothing(settings):
    calls = []
    with client_for(settings, calls, rdap_status=503, sectxt=None) as h:
        sign_in(h, "ana")
        page = h.get(URL).text
        assert "RDAP look-up failed: HTTPStatusError" in page and "No valid security.txt" in page
        n = len(calls)
        h.get(URL)
        assert len(calls) > n   # not stored: the next view tries again
    with db.connect(settings.db_path) as c:
        assert c.execute("SELECT COUNT(*) FROM kv WHERE key = ?", (domaininfo.KEY + DOM,)).fetchone()[0] == 0


def test_card_for_an_internal_zone_makes_no_lookups(settings):
    calls = []
    with client_for(replace(settings, internal_zones=(DOM,)), calls) as h:
        sign_in(h, "ana")
        page = h.get(URL).text
    assert "internal zone" in page and "Refresh" not in page and calls == []


def test_analysis_page_carries_the_card_slot(settings):
    with client_for(settings, []) as h:
        sign_in(h, "ana")
        page = h.get(f"/admin/security/analysis?domain={DOM}").text
        assert f'data-domain-card="/admin/security/domain-card" data-domain="{DOM}" hidden' in page
        assert 'data-domain-card="/admin/security/domain-card" data-domain="" hidden' in h.get(
            "/admin/security/analysis").text
        assert "data-domain-card" not in h.get("/admin/security").text   # Overview: no card
