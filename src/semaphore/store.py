"""Persistent scan state in <data_dir>/semaphore.db (SQLite) and the human-readable summary.json

Tables: images (latest scan per image), findings (every finding of that scan, alertable flag, highest tier
alerted), scans (append-only log of every scan with the finding keys added and removed), meta (also
how the TUI and the daemon talk: settings, rescan request, images being scanned)

The daemon commits after each image so the TUI sees scans as they finish. A failed send rolls its marks
back at the end of the batch
"""

from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import astuple, fields
from pathlib import Path

from .scan import TIER_RANK, Finding
from .util import now_iso, worst


def row_order(r: dict) -> tuple:
    """Sort key of State.rows: most severe first, then by name"""

    return -worst(s for s, n in (r["counts"] or {}).items() if n), r["name"] or ""


log = logging.getLogger("semaphore")
FINDING_COLS = [f.name for f in fields(Finding)]
SCHEMA = f"""
CREATE TABLE IF NOT EXISTS images (
    id TEXT PRIMARY KEY, name TEXT, containers TEXT, last_scan TEXT, counts TEXT, update_info TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    image_id TEXT NOT NULL, key TEXT NOT NULL, {", ".join(FINDING_COLS)},
    alerted TEXT, first_seen TEXT, alertable INTEGER NOT NULL DEFAULT 1, PRIMARY KEY (image_id, key)
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
        self.legacy_settings_path = data_dir / "settings.json"
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

            if "alertable" not in {
                r[1] for r in self.db.execute("PRAGMA table_info(findings)")
            }:  # DBs from before non-alertable findings were stored
                self.db.execute(
                    "ALTER TABLE findings ADD COLUMN alertable INTEGER NOT NULL DEFAULT 1"
                )

            self.import_legacy()
            self.import_legacy_settings()

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

    def import_legacy_settings(self) -> None:
        """One-time import of the old settings.json, renamed to settings.json.imported afterwards"""

        if not self.legacy_settings_path.exists() or self.settings is not None:
            return

        try:
            self.settings = json.loads(self.legacy_settings_path.read_text())
        except (OSError, ValueError):
            log.warning("settings.json unreadable, not imported")

            return

        self.save()
        self.legacy_settings_path.rename(
            self.legacy_settings_path.with_name("settings.json.imported")
        )
        log.info("Imported settings.json")

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

        rows.sort(key=row_order)

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

    def findings(self, image_id: str) -> list[tuple[str, Finding, bool]]:
        """(key, finding, alertable) for every finding of an image's last scan"""

        return [
            (key, Finding(*r[:-1]), bool(r[-1]))
            for key, *r in self.db.execute(
                f"SELECT key, {', '.join(FINDING_COLS)}, alertable FROM findings WHERE image_id = ?",
                (image_id,),
            )
        ]

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
        rest: dict[str, Finding] | None = None,
    ) -> None:
        """Stores the scan and logs it. Alerted tiers only go up, so an EPSS dipping and rising again doesn't re-alert

        update: best fixing candidate from UpdateChecker. Its "notified" digest carries over between scans
        rest: non-alertable findings, stored for display only (never marked alerted)
        """

        before = self.alerted(image_id)
        seen, was_alertable = {}, set()

        for k, first_seen, alertable in self.db.execute(
            "SELECT key, first_seen, alertable FROM findings WHERE image_id = ?",
            (image_id,),
        ):
            seen[k] = first_seen

            if alertable:
                was_alertable.add(k)

        notified = (self.update(image_id) or {}).get("notified")
        now = now_iso()
        update = {**update, "notified": notified} if update else None

        self.put_image(image_id, name, containers, now, counts, update)
        self.db.execute("DELETE FROM findings WHERE image_id = ?", (image_id,))
        self.db.executemany(
            f"INSERT INTO findings (image_id, key, {', '.join(FINDING_COLS)}, alerted, first_seen, alertable)"
            f" VALUES ({', '.join('?' * (len(FINDING_COLS) + 5))})",
            [
                (
                    image_id,
                    k,
                    *astuple(f),
                    max(f.tier, before.get(k, "normal"), key=TIER_RANK.get),
                    seen.get(k, now),
                    1,
                )
                for k, f in found.items()
            ]
            + [
                (image_id, k, *astuple(f), None, seen.get(k, now), 0)
                for k, f in (rest or {}).items()
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
                json.dumps(sorted(found.keys() - was_alertable)),
                json.dumps(sorted(was_alertable - found.keys())),
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

    @property
    def settings(self) -> dict | None:
        """Overrides edited in the TUI (Config.apply_settings), None = env only"""

        return self.get_meta("settings")

    @settings.setter
    def settings(self, settings: dict) -> None:
        self.set_meta("settings", settings)

    @property
    def scanning(self) -> list[str]:
        """Image ids the daemon is scanning in the current batch"""

        return self.get_meta("scanning") or []

    @scanning.setter
    def scanning(self, ids: list[str]) -> None:
        self.set_meta("scanning", ids)

    @property
    def rescan_request(self) -> dict | None:
        """{"images": [ids] or None for all} written by the TUI, not taken by the daemon yet"""

        return self.get_meta("rescan")

    def request_rescan(self, ids: list[str] | None) -> None:
        """Merges ids into the pending rescan request and commits. None = every image"""

        self.db.execute(
            "BEGIN IMMEDIATE"
        )  # no take_rescan between the read and the write

        pending = (self.rescan_request or {"images": []})["images"]

        self.set_meta(
            "rescan",
            {
                "images": None
                if ids is None or pending is None
                else sorted({*pending, *ids})
            },
        )
        self.save()

    def take_rescan(self) -> dict | None:
        """Pops the pending rescan request, in one statement so a request written meanwhile isn't lost"""

        row = self.db.execute(
            "DELETE FROM meta WHERE key = 'rescan' RETURNING value"
        ).fetchone()

        self.save()

        return json.loads(row[0]) if row else None
