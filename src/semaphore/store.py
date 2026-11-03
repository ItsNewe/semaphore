"""Persistent scan state in <data_dir>/semaphore.db (SQLite) and the human-readable summary.json

Tables: images (latest scan per image), findings (alertable findings of that scan with the highest tier
alerted), scans (append-only log of every scan with the finding keys added and removed), meta

Writes stay in one open transaction until save(), so a failed send rolls its marks back before they
are committed and a crash mid-batch re-alerts instead of losing alerts
"""

from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import astuple, fields
from pathlib import Path

from .scan import TIER_RANK, Finding
from .util import now_iso, worst

log = logging.getLogger("semaphore")
FINDING_COLS = [f.name for f in fields(Finding)]
SCHEMA = f"""
CREATE TABLE IF NOT EXISTS images (
    id TEXT PRIMARY KEY, name TEXT, containers TEXT, last_scan TEXT, counts TEXT, update_info TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    image_id TEXT NOT NULL, key TEXT NOT NULL, {", ".join(FINDING_COLS)},
    alerted TEXT, first_seen TEXT, PRIMARY KEY (image_id, key)
);
CREATE TABLE IF NOT EXISTS scans (
    image_id TEXT, name TEXT, scanned TEXT, counts TEXT, added TEXT, removed TEXT, update_ref TEXT
);
CREATE INDEX IF NOT EXISTS scans_image ON scans (image_id, scanned);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""


class State:
    """Per-image scan results, alert bookkeeping and scan log

    readonly: for the TUI, never writes and sees the last committed batch. Missing DB = empty state
    """

    def __init__(self, data_dir: Path, readonly: bool = False) -> None:
        self.path = data_dir / "semaphore.db"
        self.legacy_path = data_dir / "state.json"
        self.summary_path = data_dir / "summary.json"

        if readonly and self.path.exists():
            self.db = sqlite3.connect(
                f"{self.path.resolve().as_uri()}?mode=ro", uri=True
            )
        elif readonly:
            self.db = sqlite3.connect(":memory:")

            self.db.executescript(SCHEMA)
        else:
            data_dir.mkdir(parents=True, exist_ok=True)

            self.db = sqlite3.connect(self.path)

            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.executescript(SCHEMA)
            self.import_legacy()

    def save(self) -> None:
        self.db.commit()

    def import_legacy(self) -> None:
        """One-time import of the old state.json, renamed to state.json.imported afterwards
        Findings only get their key parts and alert mark, the next rescan fills in the rest"""

        if not self.legacy_path.exists() or self.ids():
            return

        try:
            data = json.loads(self.legacy_path.read_text())
        except (OSError, ValueError):
            log.warning("state.json unreadable, not imported")

            return

        for image_id, img in data.get("images", {}).items():
            alerted = img.get("alerted") or {}

            if isinstance(alerted, list):  # pre-tier state.json
                alerted = dict.fromkeys(alerted, "normal")

            self.put_image(
                image_id,
                img.get("name"),
                img.get("containers") or [],
                img.get("last_scan"),
                img.get("counts") or {},
                img.get("update"),
            )
            self.db.executemany(
                "INSERT INTO findings (image_id, key, id, pkg, version, severity, tier, alerted, first_seen)"
                " VALUES (?, ?, ?, ?, ?, 'Unknown', ?, ?, ?)",
                [
                    (
                        image_id,
                        k,
                        *(k.split("|", 2) + ["", ""])[:3],
                        t,
                        t,
                        img.get("last_scan"),
                    )
                    for k, t in alerted.items()
                ],
            )

        for k, v in data.get("meta", {}).items():
            self.set_meta(k, v)

        self.save()
        self.legacy_path.rename(self.legacy_path.with_name("state.json.imported"))
        log.info("Imported %d image(s) from state.json", len(data.get("images", {})))

    def write_summary(self) -> None:
        rows = [
            {
                "image_id": r["id"],
                **{f: r[f] for f in ("name", "containers", "counts", "last_scan")},
                "update": {"ref": u["ref"], "fixes": len(u["fixes"])}
                if (u := r["update"])
                else None,
            }
            for r in self.rows()
        ]

        self.summary_path.write_text(
            json.dumps({"generated": now_iso(), "images": rows}, indent=2)
        )

    # ------------------------------------------------------------ images

    def __contains__(self, image_id: str) -> bool:
        return bool(
            self.db.execute("SELECT 1 FROM images WHERE id = ?", (image_id,)).fetchone()
        )

    def ids(self) -> list[str]:
        return [r[0] for r in self.db.execute("SELECT id FROM images")]

    def rows(self) -> list[dict]:
        """Every image, most severe first then by name"""

        rows = [
            {
                "id": id_,
                "name": name,
                "containers": json.loads(containers),
                "last_scan": last_scan,
                "counts": json.loads(counts),
                "update": json.loads(update),
            }
            for id_, name, containers, last_scan, counts, update in self.db.execute(
                "SELECT id, name, containers, last_scan, counts, update_info FROM images"
            )
        ]

        rows.sort(
            key=lambda r: (
                -worst(s for s, n in (r["counts"] or {}).items() if n),
                r["name"] or "",
            )
        )

        return rows

    def put_image(self, image_id, name, containers, last_scan, counts, update) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO images VALUES (?, ?, ?, ?, ?, ?)",
            (
                image_id,
                name,
                json.dumps(containers),
                last_scan,
                json.dumps(counts),
                json.dumps(update),
            ),
        )

    def alerted(self, image_id: str) -> dict[str, str]:
        """{finding key: highest tier already alerted} for an image"""

        return dict(
            self.db.execute(
                "SELECT key, alerted FROM findings WHERE image_id = ? AND alerted IS NOT NULL",
                (image_id,),
            )
        )

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
        """Stores the scan and logs it. Alerted tiers only go up, so an EPSS dipping and rising again doesn't re-alert

        update: best fixing candidate from UpdateChecker. Its "notified" digest carries over between scans
        """

        before = self.alerted(image_id)
        seen = dict(
            self.db.execute(
                "SELECT key, first_seen FROM findings WHERE image_id = ?", (image_id,)
            )
        )
        notified = (self.update(image_id) or {}).get("notified")
        now = now_iso()
        update = {**update, "notified": notified} if update else None

        self.put_image(image_id, name, containers, now, counts, update)
        self.db.execute("DELETE FROM findings WHERE image_id = ?", (image_id,))
        self.db.executemany(
            f"INSERT INTO findings (image_id, key, {', '.join(FINDING_COLS)}, alerted, first_seen)"
            f" VALUES ({', '.join('?' * (len(FINDING_COLS) + 4))})",
            [
                (
                    image_id,
                    k,
                    *astuple(f),
                    max(f.tier, before.get(k, "normal"), key=TIER_RANK.get),
                    seen.get(k, now),
                )
                for k, f in found.items()
            ],
        )

        # log never pruned, add a retention window if the DB grows
        self.db.execute(
            "INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                image_id,
                name,
                now,
                json.dumps(counts),
                json.dumps(sorted(found.keys() - seen.keys())),
                json.dumps(sorted(seen.keys() - found.keys())),
                update and update["ref"],
            ),
        )

    def update(self, image_id: str) -> dict | None:
        row = self.db.execute(
            "SELECT update_info FROM images WHERE id = ?", (image_id,)
        ).fetchone()

        return json.loads(row[0]) if row else None

    def mark_update_notified(self, image_id: str) -> None:
        if u := self.update(image_id):
            u["notified"] = u["digest"]

            self.db.execute(
                "UPDATE images SET update_info = ? WHERE id = ?",
                (json.dumps(u), image_id),
            )

    def rollback(self, image_id: str, previous: dict[str, str | None]) -> None:
        """Restores alert marks after a failed send (None = never alerted), so the next rescan retries"""

        self.db.executemany(
            "UPDATE findings SET alerted = ? WHERE image_id = ? AND key = ?",
            [(tier, image_id, k) for k, tier in previous.items()],
        )

    def forget(self, image_id: str) -> str | None:
        """Drops an image's scan and alert marks (the scan log stays). Returns its name"""

        row = self.db.execute(
            "SELECT name FROM images WHERE id = ?", (image_id,)
        ).fetchone()

        self.db.execute("DELETE FROM images WHERE id = ?", (image_id,))
        self.db.execute("DELETE FROM findings WHERE image_id = ?", (image_id,))

        return row[0] if row else None

    # ------------------------------------------------------------ meta

    def get_meta(self, key: str):
        row = self.db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()

        return json.loads(row[0]) if row else None

    def set_meta(self, key: str, value) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO meta VALUES (?, ?)", (key, json.dumps(value))
        )

    @property
    def last_rescan(self) -> float | None:
        return self.get_meta("last_rescan")

    @last_rescan.setter
    def last_rescan(self, ts: float) -> None:
        self.set_meta("last_rescan", ts)

    @property
    def last_batch(self) -> dict | None:
        """Messages of the last notification batch, used by the TUI's Resend"""

        return self.get_meta("last_batch")

    @last_batch.setter
    def last_batch(self, batch: dict) -> None:
        self.set_meta("last_batch", batch)
