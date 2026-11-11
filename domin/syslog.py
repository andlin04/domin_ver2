"""Syslog forwarding of audit and security events (Settings > Logging), RFC 5424.

Off by default (no server). Options: server, port (514), UDP, TCP or TLS,
the facility and the app-name. Sent: sign-ins, sign-in failures, sign-in protection hits and every audit entry
(admin changes). Never blocks a request: messages go to a bounded in-process queue that a background thread sends;
a full queue or a failed send drops the message and counts it, and the last error shows in Settings. TCP and TLS use
octet-counting framing (RFC 6587 / RFC 5425); TLS checks the server certificate against the system CAs.

Format: <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [domin@32473 key="value" ...] MSG
(32473 is the example enterprise number of RFC 5612, as structured-data ids need one)."""
from __future__ import annotations

import json
import logging
import os
import queue
import re
import socket
import sqlite3
import ssl
import threading
from datetime import datetime
from pathlib import Path

from . import admin, db

log = logging.getLogger("domin.syslog")
KEY, STATUS_KEY = "syslog", "syslog:status"
PROTOCOLS = ("udp", "tcp", "tls")
FACILITIES = {"kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5, "lpr": 6, "news": 7,
              "uucp": 8, "cron": 9, "authpriv": 10, "ftp": 11, **{f"local{i}": 16 + i for i in range(8)}}
SEVERITIES = {"emerg": 0, "alert": 1, "crit": 2, "err": 3, "warning": 4, "notice": 5, "info": 6, "debug": 7}
DEFAULTS = {"host": "", "port": 514, "proto": "udp", "facility": "auth", "app_name": "domin"}
HOST = re.compile(r"^([A-Za-z0-9.-]{1,253}|[0-9A-Fa-f:.]{2,45})$")   # a host name or an IPv4/IPv6 address
APP_NAME = re.compile(r"^[A-Za-z0-9._-]{1,48}$")
SD_ID = "domin@32473"
UDP_MAX = 2048        # bytes per datagram (RFC 5426 recommends receivers take at least this)
QUEUE_MAX = 1000
TIMEOUT = 5.0


# --- settings ------------------------------------------------------------------------------------------------------

def config(conn: sqlite3.Connection) -> dict:
    raw = admin.kv_get(conn, KEY)
    return {**DEFAULTS, **(json.loads(raw) if raw else {})}


def validate(form: dict[str, str]) -> dict:
    """The Logging form as a config; raises ValueError with the reason. An empty server turns forwarding off."""
    host = form.get("host", "").strip()
    if host and not HOST.match(host):
        raise ValueError("Syslog server: a host name or IP address.")
    try:
        port = int(form.get("port", ""))
    except ValueError:
        raise ValueError("Port: a whole number 1-65535.") from None
    if not 1 <= port <= 65535:
        raise ValueError("Port: a whole number 1-65535.")
    proto = form.get("proto", "")
    if proto not in PROTOCOLS:
        raise ValueError("Protocol: UDP, TCP or TLS.")
    facility = form.get("facility", "")
    if facility not in FACILITIES:
        raise ValueError("Facility: one of " + ", ".join(FACILITIES) + ".")
    app_name = form.get("app_name", "").strip()
    if not APP_NAME.match(app_name):
        raise ValueError("App-name: 1-48 letters, digits, dot, dash or underscore.")
    return {"host": host, "port": port, "proto": proto, "facility": facility, "app_name": app_name}


def save(conn: sqlite3.Connection, form: dict[str, str]) -> dict:
    cfg = validate(form)
    admin.kv_set(conn, KEY, json.dumps(cfg))
    return cfg


def status(conn: sqlite3.Connection) -> dict:
    raw = admin.kv_get(conn, STATUS_KEY)
    return {"dropped": 0, "last_error": "", "error_at": "", **(json.loads(raw) if raw else {})}


# --- the message ---------------------------------------------------------------------------------------------------

def _sd_value(value) -> str:
    """A structured-data parameter value: backslash, double quote and ] escaped (RFC 5424 6.3.3); control
    characters dropped."""
    text = "".join(ch for ch in str(value) if ord(ch) >= 32)[:200]
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def _field(value: str, size: int) -> str:
    """A header field: printable US-ASCII without spaces, '-' when empty."""
    text = "".join(ch for ch in value if 33 <= ord(ch) <= 126)[:size]
    return text or "-"


def format_message(cfg: dict, severity: str, msgid: str, text: str, data: dict | None = None,
                   at: datetime | None = None, hostname: str | None = None) -> bytes:
    pri = FACILITIES[cfg["facility"]] * 8 + SEVERITIES[severity]
    stamp = (at or datetime.now().astimezone()).isoformat(timespec="milliseconds")
    params = " ".join(f'{k}="{_sd_value(v)}"' for k, v in (data or {}).items() if v not in (None, ""))
    sd = f"[{SD_ID} {params}]" if params else "-"
    msg = "".join(ch if ord(ch) >= 32 else " " for ch in text)
    head = (f"<{pri}>1 {stamp} {_field(hostname if hostname is not None else socket.gethostname(), 255)} "
            f"{_field(cfg['app_name'], 48)} {os.getpid()} {_field(msgid, 32)} {sd}")
    return (f"{head} {msg}" if msg else head).encode()


# --- sending -------------------------------------------------------------------------------------------------------

def _target(cfg: dict) -> tuple[str, int, str]:
    return cfg["host"], int(cfg["port"]), cfg["proto"]


def _open(target: tuple[str, int, str]):
    host, port, proto = target
    if proto == "udp":
        return None
    sock = socket.create_connection((host, port), timeout=TIMEOUT)
    if proto == "tls":
        sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
    return sock


def _send(sock, target: tuple[str, int, str], payload: bytes) -> None:
    host, port, proto = target
    if proto == "udp":
        family, _, _, _, addr = socket.getaddrinfo(host, port, 0, socket.SOCK_DGRAM)[0]
        with socket.socket(family, socket.SOCK_DGRAM) as u:
            u.sendto(payload[:UDP_MAX], addr)
        return
    sock.sendall(f"{len(payload)} ".encode() + payload)   # octet-counting framing


def send_now(cfg: dict, payload: bytes) -> None:
    """One message, synchronously (the Settings test button); raises OSError on failure."""
    target = _target(cfg)
    sock = _open(target)
    try:
        _send(sock, target, payload)
    finally:
        if sock:
            sock.close()


class Sender:
    """The background queue and thread of this process."""

    def __init__(self) -> None:
        self.q: queue.Queue = queue.Queue(maxsize=QUEUE_MAX)
        self.thread: threading.Thread | None = None
        self.lock = threading.Lock()
        self.sent = 0
        self.dropped = 0

    def put(self, db_path: str, target: tuple[str, int, str], payload: bytes) -> None:
        with self.lock:
            if self.thread is None or not self.thread.is_alive():
                self.thread = threading.Thread(target=self._run, name="domin-syslog", daemon=True)
                self.thread.start()
        try:
            self.q.put_nowait((db_path, target, payload))
        except queue.Full:
            self._failed(db_path, "the queue is full (the server is slow or down)")

    def _failed(self, db_path: str, error: str) -> None:
        self.dropped += 1
        log.warning("syslog message dropped: %s", error)
        try:
            with db.connect(Path(db_path)) as c:
                st = status(c)
                admin.kv_set(c, STATUS_KEY, json.dumps({"dropped": st["dropped"] + 1, "last_error": error[:300],
                                                        "error_at": db.now()}))
        except Exception:   # the status is best effort; never break the sender
            log.exception("syslog status not saved")

    def _run(self) -> None:
        sock, open_target = None, None
        while True:
            db_path, target, payload = self.q.get()
            try:
                if target != open_target:
                    if sock:
                        sock.close()
                    sock, open_target = None, None
                    sock, open_target = _open(target), target
                _send(sock, target, payload)
                self.sent += 1
            except (OSError, ValueError) as exc:
                if sock:
                    sock.close()
                sock, open_target = None, None   # reconnect with the next message
                self._failed(db_path, f"{type(exc).__name__}: {exc}")
            finally:
                self.q.task_done()


SENDER = Sender()


def _db_path(conn: sqlite3.Connection) -> str:
    return next((r[2] for r in conn.execute("PRAGMA database_list") if r[1] == "main"), "")


def emit(conn: sqlite3.Connection, severity: str, msgid: str, text: str, **data) -> None:
    """Queue one event when a server is set; never raises."""
    try:
        cfg = config(conn)
        if not cfg["host"]:
            return
        SENDER.put(_db_path(conn), _target(cfg), format_message(cfg, severity, msgid, text, data))
    except Exception:
        log.exception("syslog event not queued")
