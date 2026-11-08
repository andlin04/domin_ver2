"""Mullvad relays for routed scans, and the tunnel credentials the host's WireGuard tunnel uses.

Each Mullvad WireGuard relay runs a SOCKS5 proxy (socks_name:socks_port) that answers only inside a Mullvad tunnel
(the names resolve to 10.124.x.x). The host keeps one split tunnel up (deploy/mullvad-tunnel.sh: AllowedIPs
10.64.0.0/10 only), so a scan can leave through any relay's SOCKS5, in the country the scan settings pick.

The relay list comes from Mullvad's public API (no account) and is cached in the kv table for a day. The tunnel
credentials (account number, or a WireGuard private key with its tunnel address) are stored in the kv table too;
the unprivileged web app never touches WireGuard: saving them drops a request file in the state directory, which a
root path unit (domin-mullvad.path) turns into `mullvad-tunnel.sh apply`. That script writes a status file back.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import random
import re
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import httpx
import pycountry

from . import admin, db, tools

log = logging.getLogger("domin.mullvad")

RELAYS_URL = "https://api.mullvad.net/www/relays/all/"
RELAYS_KEY = "mullvad_relays"
TUNNEL_KEY = "mullvad_tunnel"
MAX_AGE = timedelta(hours=24)
IN_TUNNEL = ("10.64.0.1", 1080)   # Mullvad's SOCKS5 inside the tunnel: answers only when the tunnel is up
REQUEST_FILE, STATUS_FILE = "mullvad.request", "mullvad.status"
MODES = ("follow", "fixed", "auto")
MODE_NAMES = {"follow": "follow host", "fixed": "fixed", "auto": "automatic"}

_CC = re.compile(r"^[a-z]{2}$")
_CITY = re.compile(r"^[a-z]{3}$")
_SOCKS = re.compile(r"^[a-z0-9-]{1,63}\.relays\.mullvad\.net$")
_ACCOUNT = re.compile(r"^[0-9]{16}$")
_KEY = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$")   # 32 bytes in base64
TUNNEL_DEFAULT = {"account": "", "private_key": "", "address": "", "entry": ""}


class MullvadError(RuntimeError):
    """No relay can carry the scan (no list, no relay in the country)."""


# ---- relay list ----

def parse(data: object) -> list[dict]:
    """Mullvad's relay list into the WireGuard relays that have a SOCKS5 proxy (only the fields routing needs)."""
    out = []
    for r in data if isinstance(data, list) else []:
        if not isinstance(r, dict) or r.get("type") != "wireguard":
            continue
        cc, city, name = str(r.get("country_code") or "").lower(), str(r.get("city_code") or "").lower(), \
            str(r.get("socks_name") or "").lower()
        try:
            port = int(r.get("socks_port") or 0)
        except (TypeError, ValueError):
            continue
        if not (_CC.match(cc) and _SOCKS.match(name) and 1 <= port <= 65535):
            continue
        out.append({"hostname": str(r.get("hostname") or "")[:63], "country_code": cc,
                    "country_name": str(r.get("country_name") or cc)[:60], "city_code": city if _CITY.match(city)
                    else "", "city_name": str(r.get("city_name") or "")[:60], "socks_name": name,
                    "socks_port": port, "active": bool(r.get("active"))})
    return out


def fetch(client: httpx.Client) -> list[dict]:
    try:
        got = tools.get_json(client, RELAYS_URL, timeout=30)
    except (httpx.HTTPError, ValueError) as exc:
        raise MullvadError(f"cannot fetch the Mullvad relay list: {exc}") from None
    relays = parse(got[1] if got else None)
    if not relays:
        raise MullvadError("the Mullvad relay list has no WireGuard relays with SOCKS5")
    return relays


def store(conn: sqlite3.Connection, relays: list[dict]) -> None:
    admin.kv_set(conn, RELAYS_KEY, json.dumps({"fetched": db.now(), "relays": relays}))


def load(conn: sqlite3.Connection) -> tuple[list[dict], str]:
    """(relays, fetched timestamp); ([], "") when nothing is cached."""
    raw = admin.kv_get(conn, RELAYS_KEY)
    if not raw:
        return [], ""
    got = json.loads(raw)
    return got.get("relays") or [], got.get("fetched") or ""


def age(fetched: str, now: datetime | None = None) -> timedelta | None:
    if not fetched:
        return None
    return (now or datetime.now()) - datetime.fromisoformat(fetched)


def relays(conn: sqlite3.Connection, client: httpx.Client | None, now: datetime | None = None) -> list[dict]:
    """The cached list, refreshed when older than a day. A failed refresh keeps a stale list (logged); no list at all
    is a MullvadError."""
    cached, fetched = load(conn)
    a = age(fetched, now)
    if cached and a is not None and a < MAX_AGE:
        return cached
    own = client is None
    client = client or tools.http_client()
    try:
        fresh = fetch(client)
    except MullvadError as exc:
        if cached:
            log.warning("%s; using the list from %s", exc, fetched)
            return cached
        raise
    finally:
        if own:
            client.close()
    store(conn, fresh)
    conn.commit()
    return fresh


def countries(relays: list[dict]) -> list[tuple[str, str, int]]:
    """(code, name, active relays) per country, by name."""
    seen: dict[str, list] = {}
    for r in relays:
        e = seen.setdefault(r["country_code"], [r["country_code"], r["country_name"], 0])
        e[2] += r["active"]
    return sorted((tuple(e) for e in seen.values()), key=lambda e: e[1])


def cities(relays: list[dict]) -> list[tuple[str, str, str]]:
    """(country code, city code, city name), by country then city."""
    return sorted({(r["country_code"], r["city_code"], r["city_name"]) for r in relays if r["city_code"]},
                  key=lambda e: (e[0], e[2]))


def pick(relays: list[dict], cc: str, city: str = "", rng: random.Random | None = None) -> dict | None:
    """A random active relay in the country (and city); None when there is none."""
    pool = [r for r in relays if r["active"] and (not cc or r["country_code"] == cc)
            and (not city or r["city_code"] == city)]
    return (rng or random).choice(pool) if pool else None


def choose(cfg: dict, relays: list[dict], host_cc: str = "", rng: random.Random | None = None
           ) -> tuple[dict, str]:
    """The relay for one scan and how it was chosen. host_cc: the target's country (blank for an inventory job or an
    address without one).

    follow: the host's country, else the fallback country, else an error.
    fixed: the set country (and city), else an error.
    auto: the host's country, else the fallback country, else any active relay."""
    mode, fallback = cfg.get("mullvad_mode") or "auto", cfg.get("mullvad_fallback") or ""
    if mode == "fixed":
        cc, city = cfg.get("mullvad_country") or "", cfg.get("mullvad_city") or ""
        if r := pick(relays, cc, city, rng):
            return r, "fixed"
        raise MullvadError(f"no active Mullvad relay in {cc}{'-' + city if city else ''}")
    if host_cc and (r := pick(relays, host_cc, "", rng)):
        return r, MODE_NAMES[mode]
    why = f"no active Mullvad relay in {host_cc}" if host_cc else "the address has no country"
    if fallback:
        if r := pick(relays, fallback, "", rng):
            return r, f"{MODE_NAMES[mode]}: {why}, fallback"
        raise MullvadError(f"{why}, and none in the fallback country {fallback}")
    if mode == "auto" and (r := pick(relays, "", "", rng)):
        return r, f"automatic: {why}, any relay"
    raise MullvadError(f"{why}, and no fallback country is set" if mode == "follow" else "no active Mullvad relay")


def country_code(conn: sqlite3.Connection, ip: str, country: str = "") -> str:
    """The address's ISO-2 country, lower case: DB-IP first, else the record's country (a name or a code)."""
    if cc := admin.country(conn, ip):
        return cc.lower()
    if not country:
        return ""
    try:
        return pycountry.countries.lookup(country).alpha_2.lower()
    except LookupError:
        return ""


# ---- tunnel credentials ----

def get_tunnel(conn: sqlite3.Connection) -> dict:
    raw = admin.kv_get(conn, TUNNEL_KEY)
    return {**TUNNEL_DEFAULT, **(json.loads(raw) if raw else {})}


def tunnel_public(cfg: dict) -> dict:
    """For a page: whether secrets are saved, never the secrets."""
    return {"account_saved": bool(cfg.get("account")), "key_saved": bool(cfg.get("private_key")),
            "address": cfg.get("address") or "", "entry": cfg.get("entry") or ""}


def _address(text: str) -> str:
    """'10.64.1.2/32' or '10.64.1.2/32,fc00:bbbb:bbbb:bb01::1/128': an IPv4 interface address, optional IPv6."""
    parts = [p.strip() for p in text.split(",") if p.strip()]
    try:
        nets = [ipaddress.ip_interface(p) for p in parts]
    except ValueError:
        nets = []
    if not nets or "/" not in parts[0] or nets[0].version != 4 or len(nets) > 2 or \
            (len(nets) == 2 and nets[1].version != 6) or any("/" not in p for p in parts):
        raise ValueError("Tunnel address: an IPv4 address with prefix (10.64.1.2/32), optionally a comma and IPv6.")
    return ",".join(str(n) for n in nets)


def check_tunnel(form: dict[str, str], old: dict) -> dict:
    """Validate the Mullvad tunnel fields; raises ValueError. A blank secret keeps the saved one unless its clear box
    is ticked. A private key needs its tunnel address (as Mullvad's WireGuard configuration file gives them)."""
    account = (form.get("mullvad_account") or "").replace(" ", "")
    key = (form.get("mullvad_key") or "").strip()
    addr = (form.get("mullvad_address") or "").strip()
    entry = (form.get("mullvad_entry") or "").strip().lower()
    if account and not _ACCOUNT.match(account):
        raise ValueError("Mullvad account number: 16 digits.")
    if key and not _KEY.match(key):
        raise ValueError("WireGuard private key: 44 characters of base64 ending in '=' (as in a Mullvad config).")
    if entry and not _CC.match(entry):
        raise ValueError("Entry country: a two-letter country code (se, de, ...).")
    if not account and form.get("clear_mullvad_account") != "on":
        account = old.get("account", "")
    if not key and form.get("clear_mullvad_key") != "on":
        key = old.get("private_key", "")
    addr = _address(addr) if addr else ""
    if key and not addr:
        raise ValueError("A WireGuard private key needs its tunnel address (Address = ... in the Mullvad config).")
    return {"account": account, "private_key": key, "address": addr, "entry": entry}


def save_tunnel(conn: sqlite3.Connection, cfg: dict) -> bool:
    """Store checked tunnel settings; True when they changed."""
    if cfg == get_tunnel(conn):
        return False
    admin.kv_set(conn, TUNNEL_KEY, json.dumps(cfg))
    return True


def request_apply(state_dir: Path) -> Path:
    """Ask the root path unit to (re)apply the tunnel: a file with the request time only, no secrets."""
    path = Path(state_dir) / REQUEST_FILE
    tmp = path.with_suffix(".tmp")
    tmp.write_text(f"requested {db.now()}\n", encoding="utf-8")
    os.replace(tmp, path)
    return path


def apply_status(state_dir: Path) -> dict:
    """The tunnel script's last result ({at, ok, code, message}, and tunnel: {up, handshake, relay, wg, checked}),
    {} when it has not run; pending when a request waits. Files of earlier builds have no code or tunnel."""
    out: dict = {}
    try:
        got = json.loads((Path(state_dir) / STATUS_FILE).read_text(encoding="utf-8")[:4000])
        if isinstance(got, dict):
            out = {"at": str(got.get("at") or "")[:40], "ok": bool(got.get("ok")),
                   "code": str(got.get("code") or "")[:40], "message": str(got.get("message") or "")[:300]}
            t = got.get("tunnel")
            if isinstance(t, dict):
                try:
                    hs = int(t.get("handshake") or 0)
                except (TypeError, ValueError):
                    hs = 0
                out["tunnel"] = {"up": bool(t.get("up")), "handshake": hs, "wg": bool(t.get("wg")),
                                 "relay": str(t.get("relay") or "")[:63], "checked": str(t.get("checked") or "")[:40]}
    except (OSError, ValueError):
        pass
    out["pending"] = (Path(state_dir) / REQUEST_FILE).exists()
    return out


# What the script's result codes mean, in plain words, with the next step. Older status files have no code: their
# message is matched by its start (OLD_MESSAGES).
EXPLAIN = {
    "up": ("The tunnel is up.", ""),
    "down": ("The tunnel is off: no Mullvad credentials are saved.", "Save an account number below to set it up."),
    "api": ("Mullvad's API (api.mullvad.net) could not be reached from this host: the setup service has no internet "
            "or proxy.",
            "Re-install domin-mullvad.service (install.sh) so it reads the proxy from /etc/domin.env, then Apply "
            "tunnel again."),
    "refused": ("Mullvad refused to register this host's key.",
                "Check the account number (active, paid, fewer than 5 devices), then save it again."),
    "relays": ("Mullvad's relay list could not be fetched from this host: the setup service has no internet or "
               "proxy.",
               "Re-install domin-mullvad.service (install.sh) so it reads the proxy from /etc/domin.env, then Apply "
               "tunnel again."),
    "no-relay": ("No active Mullvad WireGuard relay in the entry country.", "Clear or change the entry country."),
    "no-handshake": ("The tunnel was configured but the relay never answered (no WireGuard handshake): this host "
                     "likely can't send UDP 51820 to the internet (proxy-only egress?). The tunnel was taken down "
                     "again.",
                     "Allow outbound UDP 51820 from this host in the firewall, or use Tor or a custom proxy instead."),
    "no-socks": ("The tunnel is up but Mullvad's SOCKS5 inside it (10.64.0.1:1080) does not answer.",
                 "Apply tunnel again (another relay is picked)."),
    "packages": ("A program the tunnel needs is missing on this host.",
                 "apt install wireguard-tools curl python3, then Apply tunnel again."),
    "credentials": ("The saved credentials can't be used.", "Correct them below and save."),
    "step": ("The setup script stopped with an error.", "Look at journalctl -u domin-mullvad on the host."),
}
OLD_MESSAGES = (("key registration: the Mullvad API did not answer", "api"), ("key registration refused", "refused"),
                ("cannot fetch the Mullvad relay list", "relays"), ("no active WireGuard relay", "no-relay"),
                ("tunnel up via", "up"), ("tunnel down", "down"), ("failed at:", "step"),
                ("no Mullvad credentials", "credentials"))


def explain(status: dict) -> dict:
    """The last apply in plain words: {ok, text, next, detail}; {} when it has not run."""
    if not status.get("at"):
        return {}
    msg = status.get("message") or ""
    code = status.get("code") or next((c for start, c in OLD_MESSAGES if msg.startswith(start)), "")
    if code not in EXPLAIN:
        return {"ok": status.get("ok", False), "text": msg or "No message.", "next": "", "detail": ""}
    text, step = EXPLAIN[code]
    if code == "up" and msg:
        text = msg[0].upper() + msg[1:] + "."
    return {"ok": status.get("ok", False), "text": text, "next": step,
            "detail": msg if code in ("refused", "credentials", "packages", "step", "no-relay", "no-socks") else ""}


def tunnel_summary(status: dict, socks_ok: bool) -> dict:
    """The tunnel's state for the page: {ok, text}. ok: the in-tunnel SOCKS5 answers (a Mullvad route can work)."""
    t = status.get("tunnel") or {}
    relay = f" via {t['relay']}" if t.get("relay") else ""
    if socks_ok:
        return {"ok": True, "text": f"up{relay}; Mullvad's SOCKS5 inside it ({IN_TUNNEL[0]}:{IN_TUNNEL[1]}) answers"}
    if t.get("up") and not t.get("handshake"):
        return {"ok": False, "text": f"interface up{relay} but no handshake with the relay: outbound UDP 51820 "
                                     "blocked?"}
    if t.get("up"):
        return {"ok": False, "text": f"interface up{relay}, but Mullvad's SOCKS5 inside it does not answer"}
    last = explain(status)
    if last and not last["ok"]:
        return {"ok": False, "text": f"not up: {last['text'].rstrip('.')}"}
    return {"ok": False, "text": "not set up (save a Mullvad account number under Mullvad tunnel)"}
