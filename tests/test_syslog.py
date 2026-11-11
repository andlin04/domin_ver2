"""Syslog forwarding (domin.syslog): the RFC 5424 format, delivery to a local UDP receiver, the settings."""
import json
import re
import socket
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from domin import access, admin, db, syslog, users
from domin.config import Settings
from domin.web import COOKIE, create_app

BASE = "/admin"
PW = "correct horse battery"
CFG = {"host": "127.0.0.1", "port": 514, "proto": "udp", "facility": "auth", "app_name": "domin"}
RFC5424 = re.compile(r"^<(\d{1,3})>1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|\[.*\])(?: (.*))?$", re.S)


@pytest.fixture
def settings(tmp_path):
    s = replace(Settings.from_env(), db_path=tmp_path / "t.db", admin_ips=(), internal_ips=())
    db.init(s.db_path)
    with db.connect(s.db_path) as c:
        users.create(c, "boss", "admin", PW)
    return s


@pytest.fixture
def receiver():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(0.2)
    yield sock
    sock.close()


def received(sock, want: str, deadline: float = 5.0) -> str:
    """The first datagram that contains want, polling until the deadline."""
    end = time.monotonic() + deadline
    while time.monotonic() < end:
        try:
            text = sock.recv(4096).decode("utf-8")
        except TimeoutError:
            continue
        if want in text:
            return text
    raise AssertionError(f"no syslog message with {want!r}")


def client(settings):
    return TestClient(create_app(settings), base_url="https://testserver", client=("203.0.113.9", 50000))


def login(h):
    r = h.post(BASE + "/login", data={"name": "boss", "password": PW}, follow_redirects=False)
    assert r.status_code == 303 and COOKIE in r.cookies


def csrf_of(h, path=BASE + "/settings/logging"):
    return re.search(r'name="csrf" value="([^"]+)"', h.get(path).text).group(1)


def set_cfg(settings, **kw):
    with db.connect(settings.db_path) as c:
        admin.kv_set(c, syslog.KEY, json.dumps({**CFG, **kw}))


# --- the format ----------------------------------------------------------------------------------------------------

def test_rfc5424_format():
    at = datetime(2026, 11, 11, 9, 30, 0, 123000, tzinfo=timezone(timedelta(hours=1)))
    raw = syslog.format_message(CFG, "warning", "signin-fail", "sign-in failed",
                                {"user": 'a"b]c\\d', "ip": "192.0.2.1", "empty": ""}, at=at, hostname="host one")
    m = RFC5424.match(raw.decode())
    assert m, raw
    pri, stamp, host, app, procid, msgid, sd, msg = m.groups()
    assert int(pri) == 4 * 8 + 4   # auth.warning
    assert stamp == "2026-11-11T09:30:00.123+01:00"
    assert host == "hostone" and app == "domin" and procid.isdigit() and msgid == "signin-fail"
    assert sd == '[domin@32473 user="a\\"b\\]c\\\\d" ip="192.0.2.1"]'   # escaped; empty values left out
    assert msg == "sign-in failed"
    bare = syslog.format_message({**CFG, "facility": "local7"}, "info", "x", "", hostname="")
    assert re.match(r"^<190>1 \S+ - domin \d+ x -$", bare.decode())   # local7.info, no host, no SD, no MSG


# --- delivery ------------------------------------------------------------------------------------------------------

def test_events_reach_a_local_udp_receiver(settings, receiver):
    set_cfg(settings, port=receiver.getsockname()[1], app_name="domin-test")
    with client(settings) as h:
        h.post(BASE + "/login", data={"name": "boss", "password": "wrong"})
        fail = received(receiver, "signin-fail")
        assert fail.startswith(f"<{4 * 8 + 4}>1 ") and " domin-test " in fail
        assert 'user="boss"' in fail and 'ip="203.0.113.9"' in fail
        login(h)
        assert 'user="boss"' in received(receiver, " signin ")
        csrf = csrf_of(h, BASE + "/users")
        h.post(BASE + "/users/add", data={"csrf": csrf, "name": "neo", "role": "admin", "password": PW,
                                           "confirm": PW})
        audit_msg = received(receiver, "user-add")
        assert " audit " in audit_msg and 'target="neo"' in audit_msg and PW not in audit_msg


def test_off_by_default_sends_nothing(settings, receiver):
    with db.connect(settings.db_path) as c:
        assert syslog.config(c)["host"] == ""
    before = syslog.SENDER.q.qsize(), syslog.SENDER.sent
    with client(settings) as h:
        login(h)
        page = h.get(BASE + "/settings/logging").text
    assert "Syslog server" in page and 'pill fix-no">off' in page and "Dropped events: <b>0</b>" in page
    assert (syslog.SENDER.q.qsize(), syslog.SENDER.sent) == before


def test_a_failed_send_is_dropped_counted_and_shown(settings, monkeypatch):
    set_cfg(settings, proto="tcp", port=9)   # tests refuse every connection (conftest)
    with db.connect(settings.db_path) as c:
        syslog.emit(c, "info", "x", "one")
    end = time.monotonic() + 5
    while time.monotonic() < end:
        with db.connect(settings.db_path) as c:
            st = syslog.status(c)
        if st["dropped"]:
            break
        time.sleep(0.05)
    assert st["dropped"] == 1 and "ConnectionRefusedError" in st["last_error"]
    with client(settings) as h:
        login(h)
        assert "ConnectionRefusedError" in h.get(BASE + "/settings/logging").text


def test_the_test_button(settings, receiver):
    with client(settings) as h:
        login(h)
        csrf = csrf_of(h)
        assert h.post(BASE + "/settings/logging/test", data={"csrf": csrf}).status_code == 422   # no server yet
        set_cfg(settings, port=receiver.getsockname()[1])
        r = h.post(BASE + "/settings/logging/test", data={"csrf": csrf})
        assert r.status_code == 200 and "Test message sent to 127.0.0.1" in r.text
        assert "domin test message from boss" in received(receiver, " test ")
        assert h.post(BASE + "/settings/logging/test", data={"csrf": "x"}).status_code == 403


# --- settings ------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("bad", [{"host": "bad host!"}, {"port": "0"}, {"port": "70000"}, {"port": "x"},
                                 {"proto": "http"}, {"facility": "local9"}, {"app_name": "has space"},
                                 {"app_name": "x" * 49}])
def test_settings_validation(settings, bad):
    with client(settings) as h:
        login(h)
        form = {"csrf": csrf_of(h), "host": "syslog.example.org", "port": "6514", "proto": "tls",
                "facility": "authpriv", "app_name": "domin"}
        assert h.post(BASE + "/settings/logging", data={**form, **bad}).status_code == 422
        r = h.post(BASE + "/settings/logging", data=form, follow_redirects=False)
        assert r.status_code == 303
    with db.connect(settings.db_path) as c:
        assert syslog.config(c) == {"host": "syslog.example.org", "port": 6514, "proto": "tls",
                                    "facility": "authpriv", "app_name": "domin"}
        assert any(a["action"] == "logging" for a in access.audit_recent(c))
        admin.kv_set(c, syslog.KEY, json.dumps({**CFG, "host": ""}))   # empty server: off again
        assert syslog.config(c)["host"] == ""
