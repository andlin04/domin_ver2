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
    queue_max: int = 50        # POST /api/scan refuses new jobs while this many are queued (all clients)
    lookups_per_minute: int = 30   # per client IP, for /api/rdap and /api/email

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
            lookups_per_minute=int(env("DOMIN_LOOKUPS_PER_MINUTE", "30")),
        )
