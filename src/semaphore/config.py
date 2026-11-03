"""Settings, read once from the environment"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

SEV_RANK = {
    "unknown": 0,
    "negligible": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}


def env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)

    return default if v is None else v.strip().lower() in ("1", "true", "yes", "on")


def env_hours(name: str, default: float) -> float:
    """Reads an hours setting and returns seconds"""

    return float(os.getenv(name, str(default))) * 3600


@dataclass(frozen=True)
class Config:
    data_dir: Path = Path("/data")
    apprise_urls: str = ""
    apprise_urls_urgent: str = ""
    min_severity: str = "high"
    epss_threshold: float = 0.1
    only_fixed: bool = False
    skip_wont_fix: bool = True
    scan_on_pull: bool = False
    notify_on_start: bool = False
    prune_removed: bool = True
    check_updates: bool = True
    rescan_interval: float = 24 * 3600
    reconcile_interval: int = 300
    db_update_interval: float = 6 * 3600
    max_lines: int = 5
    max_body: int = 1800
    syft_timeout: int = 1800
    grype_timeout: int = 600
    db_update_timeout: int = 900
    crane_timeout: int = 120
    grype_config: Path = Path("/config/grype.yaml")
    exclude: re.Pattern | None = None

    def __post_init__(self) -> None:
        if self.min_severity not in SEV_RANK:
            raise SystemExit(f"MIN_SEVERITY must be one of: {', '.join(SEV_RANK)}")

    @property
    def min_rank(self) -> int:
        return SEV_RANK[self.min_severity]

    @property
    def sbom_dir(self) -> Path:
        return self.data_dir / "sboms"

    @property
    def report_dir(self) -> Path:
        return self.data_dir / "reports"

    @classmethod
    def from_env(cls) -> Config:
        exclude = os.getenv("EXCLUDE_IMAGES", "").strip()

        return cls(
            data_dir=Path(os.getenv("DATA_DIR", "/data")),
            apprise_urls=os.getenv("APPRISE_URLS", "").strip(),
            apprise_urls_urgent=os.getenv("APPRISE_URLS_URGENT", "").strip(),
            min_severity=os.getenv("MIN_SEVERITY", "High").strip().lower(),
            epss_threshold=float(os.getenv("EPSS_THRESHOLD", "0.1")),
            only_fixed=env_bool("ONLY_FIXED"),
            skip_wont_fix=env_bool("SKIP_WONT_FIX", True),
            scan_on_pull=env_bool("SCAN_ON_PULL"),
            notify_on_start=env_bool("NOTIFY_ON_START"),
            prune_removed=env_bool("PRUNE_REMOVED_IMAGES", True),
            check_updates=env_bool("CHECK_UPDATES", True),
            rescan_interval=env_hours("RESCAN_INTERVAL_HOURS", 24),
            reconcile_interval=int(os.getenv("RECONCILE_INTERVAL_SECONDS", "300")),
            db_update_interval=env_hours("DB_UPDATE_INTERVAL_HOURS", 6),
            max_lines=int(os.getenv("ALERT_MAX_LINES_PER_IMAGE", "5")),
            max_body=int(os.getenv("ALERT_MAX_CHARS", "1800")),
            syft_timeout=int(os.getenv("SYFT_TIMEOUT_SECONDS", "1800")),
            grype_timeout=int(os.getenv("GRYPE_TIMEOUT_SECONDS", "600")),
            crane_timeout=int(os.getenv("CRANE_TIMEOUT_SECONDS", "120")),
            grype_config=Path(os.getenv("GRYPE_CONFIG", "/config/grype.yaml")),
            exclude=re.compile(exclude) if exclude else None,
        )
