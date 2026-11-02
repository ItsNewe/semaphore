"""Helper functions"""
from __future__ import annotations

import logging
import subprocess
from datetime import datetime, timezone

from .config import SEV_RANK

log = logging.getLogger("semaphore")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def hex_id(image_id: str) -> str:
    return image_id.split(":", 1)[-1]


def rank(sev: str) -> int:
    return SEV_RANK.get((sev or "unknown").lower(), 0)


def worst(sevs) -> int:
    """Highest severity rank in an iterable of severity names (0 if empty)"""
    return max((rank(s) for s in sevs), default=0)


def plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def run_tool(cmd: list[str], timeout: int, **kwargs) -> str:
    """Runs a CLI tool and returns its stdout. Raises RuntimeError on failure or timeout"""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kwargs)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"{cmd[0]} timed out after {timeout}s") from None
    if r.returncode != 0:
        raise RuntimeError(f"{cmd[0]} failed: {(r.stderr or r.stdout).strip()[-500:]}")
    return r.stdout


def safe(fn, *args, **kwargs) -> None:
    try:
        fn(*args, **kwargs)
    except Exception as e:  # one bad image must not stop the batch
        log.error("%s", e)
        log.debug("details", exc_info=True)
