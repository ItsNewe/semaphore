"""Persistent scan state (state.json) and the human-readable summary.json"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from .scan import TIER_RANK, Finding
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

        for img in self.images.values():
            if isinstance(img.get("alerted"), list):  # pre-tier state.json
                img["alerted"] = dict.fromkeys(img["alerted"], "normal")

    def save(self) -> None:
        tmp = self.path.with_suffix(".tmp")

        tmp.write_text(
            json.dumps(
                {"images": self.images, "meta": self.meta}, indent=2, sort_keys=True
            )
        )
        tmp.replace(self.path)

    def write_summary(self) -> None:
        rows = [
            {
                "image_id": k,
                **{f: v.get(f) for f in ("name", "containers", "counts", "last_scan")},
                "update": {"ref": u["ref"], "fixes": len(u["fixes"])}
                if (u := v.get("update"))
                else None,
            }
            for k, v in self.images.items()
        ]

        rows.sort(
            key=lambda r: (
                -worst(s for s, n in (r["counts"] or {}).items() if n),
                r["name"] or "",
            )
        )
        self.summary_path.write_text(
            json.dumps({"generated": now_iso(), "images": rows}, indent=2)
        )

    # ------------------------------------------------------------ images

    def __contains__(self, image_id: str) -> bool:
        return image_id in self.images

    def alerted(self, image_id: str) -> dict[str, str]:
        """{finding key: highest tier already alerted} for an image"""

        return dict(self.images.get(image_id, {}).get("alerted", {}))

    def new_findings(
        self, image_id: str, found: dict[str, Finding]
    ) -> dict[str, Finding]:
        """Findings never alerted, or escalated since (normal -> urgent, e.g. newly added to KEV)"""

        before = self.alerted(image_id)

        return {
            k: f
            for k, f in found.items()
            if k not in before or TIER_RANK[f.tier] > TIER_RANK[before[k]]
        }

    def record_scan(
        self,
        image_id: str,
        name: str,
        containers: list[str],
        counts: dict,
        found: dict[str, Finding],
        update: dict | None = None,
    ) -> None:
        """Stores the scan. Alerted tiers only go up, so an EPSS dipping and rising again doesn't re-alert

        update: best fixing candidate from UpdateChecker. Its "notified" digest carries over between scans
        """

        before = self.alerted(image_id)
        notified = (self.update(image_id) or {}).get("notified")
        self.images[image_id] = {
            "name": name,
            "containers": containers,
            "last_scan": now_iso(),
            "counts": counts,
            "alerted": {
                k: max(f.tier, before.get(k, "normal"), key=TIER_RANK.get)
                for k, f in found.items()
            },
            "update": {**update, "notified": notified} if update else None,
        }

    def update(self, image_id: str) -> dict | None:
        return self.images.get(image_id, {}).get("update")

    def mark_update_notified(self, image_id: str) -> None:
        if u := self.update(image_id):
            u["notified"] = u["digest"]

    def rollback(self, image_id: str, previous: dict[str, str | None]) -> None:
        """Restores alert marks after a failed send (None = never alerted), so the next rescan retries"""

        img = self.images.get(image_id)

        if not img:
            return

        for k, tier in previous.items():
            if tier is None:
                img["alerted"].pop(k, None)
            else:
                img["alerted"][k] = tier

    def forget(self, image_id: str) -> dict | None:
        return self.images.pop(image_id, None)

    @property
    def last_rescan(self) -> float | None:
        return self.meta.get("last_rescan")

    @last_rescan.setter
    def last_rescan(self, ts: float) -> None:
        self.meta["last_rescan"] = ts
