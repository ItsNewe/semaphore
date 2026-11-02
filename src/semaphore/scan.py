"""Syft (SBOM) and Grype (vulnerability matching) wrappers, plus parsing of Grype output"""
from __future__ import annotations

import json
import logging
import os
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .config import Config
from .util import hex_id, rank, run_tool

log = logging.getLogger("semaphore")


@dataclass
class Finding:
    id: str
    severity: str
    pkg: str
    version: str
    fix: str
    url: str


class Scanner:
    def __init__(self, config: Config) -> None:
        self.config = config
        self._last_db_update = 0.0

    def artifact(self, image_id: str, kind: str) -> Path:
        """Path of a per-image file. kind: syft.json, cdx.json, grype.json, or a .partial temp"""
        directory = self.config.report_dir if kind == "grype.json" else self.config.sbom_dir
        return directory / f"{hex_id(image_id)}.{kind}"

    def artifacts(self, image_id: str) -> list[Path]:
        """Every file stored for an image"""
        h = hex_id(image_id)
        return [p for d in (self.config.sbom_dir, self.config.report_dir) for p in d.glob(f"{h}.*")]

    def has_sbom(self, image_id: str) -> bool:
        return self.artifact(image_id, "syft.json").exists()

    def ensure_db(self, force: bool = False) -> None:
        if not force and time.time() - self._last_db_update < self.config.db_update_interval:
            return

        log.info("Updating Grype vulnerability DB")
        try:
            run_tool(["grype", "db", "update"], self.config.db_update_timeout)
            self._last_db_update = time.time()
        except RuntimeError as e:
            log.warning("%s", e)

    def generate_sbom(self, image_id: str, refs: list[str]) -> None:
        """Writes <id>.syft.json and <id>.cdx.json, trying each ref until syft can read the image"""
        out_json, out_cdx = self.artifact(image_id, "syft.json"), self.artifact(image_id, "cdx.json")
        tmp_json, tmp_cdx = self.artifact(image_id, "syft.partial"), self.artifact(image_id, "cdx.partial")
        last_err = ""
        for ref in refs:
            log.info("Generating SBOM for %s", ref)
            try:
                run_tool(["syft", "scan", "--from", "docker", ref, "-q",
                          "-o", f"syft-json={tmp_json}", "-o", f"cyclonedx-json={tmp_cdx}"],
                         self.config.syft_timeout)
            except RuntimeError as e:
                last_err = str(e)
                log.debug("ref %s: %s", ref, e)
                continue

            if tmp_json.exists():
                if tmp_cdx.exists():
                    tmp_cdx.replace(out_cdx)
                tmp_json.replace(out_json)  # written last: its presence marks the SBOM as complete
                return
            last_err = "syft produced no output"

        tmp_json.unlink(missing_ok=True)
        tmp_cdx.unlink(missing_ok=True)
        raise RuntimeError(f"syft could not read image {hex_id(image_id)[:12]}: {last_err}")

    def grype_scan(self, image_id: str) -> dict:
        """Matches the stored SBOM against the DB; saves and returns the raw report"""
        cmd = ["grype", f"sbom:{self.artifact(image_id, 'syft.json')}", "-o", "json", "-q", "--by-cve"]
        if self.config.only_fixed:
            cmd.append("--only-fixed")
        if self.config.grype_config.is_file():
            cmd += ["-c", str(self.config.grype_config)]

        env = {**os.environ, "GRYPE_DB_AUTO_UPDATE": "false"}  # DB is refreshed by ensure_db()
        out = run_tool(cmd, self.config.grype_timeout, env=env)
        self.artifact(image_id, "grype.json").write_text(out)
        return json.loads(out)


def parse_matches(report: dict, min_rank: int) -> tuple[dict[str, Finding], dict]:
    """Returns (findings at/above min_rank keyed by vuln|pkg|version, counts for all severities)"""
    unique: dict = {}
    for m in report.get("matches", []):
        v, a = m.get("vulnerability", {}), m.get("artifact", {})
        sev = (v.get("severity") or "Unknown").capitalize()
        unique.setdefault(f'{v.get("id")}|{a.get("name")}|{a.get("version")}', (sev, v, a))

    counts = dict(Counter(sev for sev, _, _ in unique.values()))
    found = {
        key: Finding(
            id=v.get("id"),
            severity=sev,
            pkg=a.get("name"),
            version=a.get("version"),
            fix=", ".join((v.get("fix") or {}).get("versions") or []),
            url=v.get("dataSource", ""),
        )
        for key, (sev, v, a) in unique.items()
        if rank(sev) >= min_rank
    }
    return found, counts
