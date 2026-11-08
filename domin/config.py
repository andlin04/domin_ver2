"""Settings from the environment (DOMIN_*); defaults suit a local run."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


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
    admin_ips: tuple[str, ...] = ()   # addresses/networks that see /admin and its link; empty = no admin page
    internal_ips: tuple[str, ...] = ()   # private API clients (over a VPN): POST /api/scan without visitor limits
    internal_zones: tuple[str, ...] = ()   # domain suffixes scanned internally: resolve via internal_dns, no egress
    internal_dns: tuple[str, ...] = ()   # resolver addresses for internal scans (the LAN DNS server)
    internal_nets: tuple[str, ...] = ()   # internal scans: networks whose addresses are reverse-looked-up for names
    cve_db_mode: str = "own"      # own = this instance maintains its CVE database; shared = read one from elsewhere
    cve_db_path: str = ""         # shared mode: the database file to read; own mode: defaults next to db_path
    cve_ttl_days: int = 7         # own mode: re-query a target whose cached result is older than this
    nvd_api_key: str = ""         # optional, raises the NVD rate limit

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
        )
