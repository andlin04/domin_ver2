"""Settings from the environment (DOMIN_*); defaults suit a local run."""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path

COMPONENTS = ("inventory", "posture")   # install.sh --components; the default installs both


def parse_components(text: str) -> tuple[str, ...]:
    """DOMIN_COMPONENTS ("inventory,posture"): the known names in their fixed order; empty or none known = both."""
    names = {x.strip().lower() for x in (text or "").split(",")}
    return tuple(c for c in COMPONENTS if c in names) or COMPONENTS


TOTP_KEY = "/etc/domin/totp.key"   # install.sh / update.sh create it (root:domin 0640); tests point DOMIN_TOTP_KEY away


def totp_key_path() -> Path:
    """The two-factor encryption key file (domin.secretbox): DOMIN_TOTP_KEY, else /etc/domin/totp.key."""
    return Path(os.environ.get("DOMIN_TOTP_KEY", "").strip() or TOTP_KEY)


@dataclass(frozen=True)
class Settings:
    db_path: Path
    refresh_days: int          # re-scan domains whose last scan is older than this; 0 = off
    scan_workers: int          # parallel DNS lookups per scan
    max_hosts: int             # cap on candidate host names per scan
    scans_per_hour: int        # per client IP, for POST /api/scan
    amass: str                 # path to amass, used for passive discovery when it exists
    queue_max: int = 50        # POST /api/scan refuses new jobs while this many visitor jobs are queued
    scans_per_day: int = 200   # per client IP, for POST /api/scan
    scans_per_day_total: int = 500   # visitor scans in 24 h from all clients together (abuse from many addresses)
    user_workers: int = 3      # parallel scans for visitors' jobs
    refresh_workers: int = 2   # parallel scans for scheduled refreshes (never take visitors' jobs)
    scan_timeout_hours: int = 3    # a longer scan fails at its next progress step
    lookups_per_minute: int = 30   # per client IP, for /api/rdap and /api/email
    once_per_day: bool = True      # POST /api/scan: each domain at most once per day
    scan_limits_off: bool = False  # POST /api/scan: skip all visitor limits (once-per-day, rate, quota, queue)
    scans_paused: bool = False     # the worker leaves queued jobs waiting
    posture_parallel: int = 1      # posture scans running at once (up to POSTURE_SLOTS worker threads)
    analytics_days: int = 180      # visit statistics older than this are deleted
    admin_ips: tuple[str, ...] = ()   # optional network allowlist for /admin; empty = sign-in alone
    internal_ips: tuple[str, ...] = ()   # private API clients (over a VPN): POST /api/scan without visitor limits
    internal_zones: tuple[str, ...] = ()   # domain suffixes scanned internally: resolve via internal_dns, no egress
    internal_dns: tuple[str, ...] = ()   # resolver addresses for internal scans (the LAN DNS server)
    internal_nets: tuple[str, ...] = ()   # internal scans: networks whose addresses are reverse-looked-up for names
    cve_db_mode: str = "own"      # own = this instance maintains its CVE database; shared = read one from elsewhere
    cve_db_path: str = ""         # shared mode: the database file to read; own mode: defaults next to db_path
    cve_ttl_days: int = 7         # own mode: re-query a target whose cached result is older than this
    nvd_api_key: str = ""         # optional, raises the NVD rate limit
    hide_signin_link: bool = False  # no "Sign in" link in the menu (public sites); /admin still works by URL
    allow_no_login: bool = False  # dev/lab only: Settings may turn sign-in off (every visitor acts as that admin)
    install_mode: str = "public"  # install.sh: "internal" (on-prem, --internal) or "public"
    scan_nets: tuple[str, ...] = ()   # on-prem: private networks the scans may reach (install --scan-nets)
    components: tuple[str, ...] = COMPONENTS   # installed parts (install.sh --components); Settings turns them on/off
    totp_key: Path = Path(TOTP_KEY)   # two-factor secrets' encryption key (read per use by domin.secretbox)

    @property
    def internal_mode(self) -> bool:
        return self.install_mode == "internal"

    def no_login_refusal(self) -> str:
        """Why DOMIN_ALLOW_NO_LOGIN is refused here ('' = accepted). It needs the DOMIN_ADMIN_IPS allowlist (the
        stand-in session then counts only for those addresses); a public install accepts private networks only
        there, so the stand-in is never reachable from the internet."""
        if not self.allow_no_login:
            return ""
        if not self.admin_ips:
            return "DOMIN_ADMIN_IPS is empty"
        if not self.internal_mode:
            for n in self.admin_ips:
                try:
                    private = ipaddress.ip_network(n, strict=False).is_private
                except ValueError:
                    private = False
                if not private:
                    return f"public install: DOMIN_ADMIN_IPS holds a non-private network ({n})"
        return ""

    @property
    def cve_db_file(self) -> Path:
        return Path(self.cve_db_path) if self.cve_db_path else self.db_path.parent / "cve_db.json"

    @classmethod
    def from_env(cls) -> Settings:
        env = os.environ.get
        return cls(
            db_path=Path(env("DOMIN_DB", "domin.db")),
            refresh_days=int(env("DOMIN_REFRESH_DAYS", "0")),
            scan_workers=int(env("DOMIN_SCAN_WORKERS", "20")),
            max_hosts=int(env("DOMIN_MAX_HOSTS", "3000")),
            scans_per_hour=int(env("DOMIN_SCANS_PER_HOUR", "10")),
            amass=env("DOMIN_AMASS", "/usr/local/bin/amass"),
            queue_max=int(env("DOMIN_QUEUE_MAX", "50")),
            scans_per_day=int(env("DOMIN_SCANS_PER_DAY", "200")),
            scans_per_day_total=int(env("DOMIN_SCANS_PER_DAY_TOTAL", "500")),
            user_workers=int(env("DOMIN_USER_WORKERS", "3")),
            refresh_workers=int(env("DOMIN_REFRESH_WORKERS", "2")),
            scan_timeout_hours=int(env("DOMIN_SCAN_TIMEOUT_HOURS", "3")),
            lookups_per_minute=int(env("DOMIN_LOOKUPS_PER_MINUTE", "30")),
            analytics_days=int(env("DOMIN_ANALYTICS_DAYS", "180")),
            scan_limits_off=env("DOMIN_SCAN_LIMITS_OFF", "").strip().lower() in ("1", "true", "yes", "on"),
            admin_ips=tuple(x.strip() for x in env("DOMIN_ADMIN_IPS", "").split(",") if x.strip()),
            internal_ips=tuple(x.strip() for x in env("DOMIN_INTERNAL_IPS", "").split(",") if x.strip()),
            internal_zones=tuple(x.strip().lower().strip(".") for x in env("DOMIN_INTERNAL_ZONES", "").split(",")
                                 if x.strip()),
            internal_dns=tuple(x.strip() for x in env("DOMIN_INTERNAL_DNS", "").split(",") if x.strip()),
            internal_nets=tuple(x.strip() for x in env("DOMIN_INTERNAL_NETS", "").split(",") if x.strip()),
            cve_db_mode="shared" if env("DOMIN_CVE_DB_MODE", "own").strip().lower() == "shared" else "own",
            cve_db_path=env("DOMIN_CVE_DB_PATH", "").strip(),
            cve_ttl_days=int(env("DOMIN_CVE_TTL_DAYS", "7")),
            nvd_api_key=env("DOMIN_NVD_API_KEY", "").strip(),
            hide_signin_link=env("DOMIN_HIDE_SIGNIN_LINK", "").strip().lower() in ("1", "true", "yes", "on"),
            allow_no_login=env("DOMIN_ALLOW_NO_LOGIN", "").strip().lower() in ("1", "true", "yes", "on"),
            install_mode="internal" if env("DOMIN_INSTALL_MODE", "").strip().lower() == "internal" else "public",
            scan_nets=tuple(x.strip() for x in env("DOMIN_SCAN_NETS", "").split(",") if x.strip()),
            components=parse_components(env("DOMIN_COMPONENTS", "")),
            totp_key=totp_key_path(),
        )
