"""Persistent scan state (state.json) and the human-readable summary.json"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from .util import now_iso, worst

log = logging.getLogger("semaphore")


class State:
    """Per-image scan results and alert bookkeeping, persisted to <data_dir>/state.json"""

    def __init__(self, data_dir: Path) -> None:
        self.path = data_dir / "state.json"
        self.summary_path = data_dir / "summary.json"
        self.images: dict[str, dict] = {}
        self.meta: dict = {}

    # ------------------------------------------------------------ persistence

    def load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text())
        except (OSError, ValueError):
            log.warning("state.json unreadable, starting fresh")
            return
        self.images = data.get("images", {})
        self.meta = data.get("meta", {})

    def save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"images": self.images, "meta": self.meta}, indent=2, sort_keys=True))
        tmp.replace(self.path)

    def write_summary(self) -> None:
        rows = [
            {"image_id": k, **{f: v.get(f) for f in ("name", "containers", "counts", "last_scan")}}
            for k, v in self.images.items()
        ]
        rows.sort(key=lambda r: (-worst(s for s, n in (r["counts"] or {}).items() if n), r["name"] or ""))
        self.summary_path.write_text(json.dumps({"generated": now_iso(), "images": rows}, indent=2))

    # ------------------------------------------------------------ images

    def __contains__(self, image_id: str) -> bool:
        return image_id in self.images

    def record_scan(self, image_id: str, name: str, containers: list[str], counts: dict, alerted) -> None:
        self.images[image_id] = {
            "name": name,
            "containers": containers,
            "last_scan": now_iso(),
            "counts": counts,
            "alerted": sorted(alerted),
        }

    def alerted(self, image_id: str) -> set[str]:
        return set(self.images.get(image_id, {}).get("alerted", []))

    def rollback(self, image_id: str, keys) -> None:
        """Un-marks findings whose alert failed, so the next rescan reports them again"""
        img = self.images.get(image_id)
        if img:
            img["alerted"] = sorted(set(img["alerted"]) - set(keys))

    def forget(self, image_id: str) -> dict | None:
        return self.images.pop(image_id, None)

    @property
    def last_rescan(self) -> float | None:
        return self.meta.get("last_rescan")

    @last_rescan.setter
    def last_rescan(self, ts: float) -> None:
        self.meta["last_rescan"] = ts
