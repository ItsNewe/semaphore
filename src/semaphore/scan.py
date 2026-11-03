"""Syft (SBOM) and Grype (vulnerability matching) wrappers, plus parsing of Grype output"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .config import Config
from .util import hex_id, rank, run_tool

log = logging.getLogger("semaphore")
TIER_RANK = {"normal": 0, "urgent": 1}

# CWE + keyword heuristic. Memory corruption (CWE-787/416/...) stays unclassified
# unless the description says code execution; most of those are crashes in practice
RCE_CWES = {
    "CWE-77",
    "CWE-78",
    "CWE-94",
    "CWE-95",
    "CWE-434",
    "CWE-502",
    "CWE-917",
    "CWE-1336",
}
DOS_CWES = {
    "CWE-400",
    "CWE-407",
    "CWE-476",
    "CWE-674",
    "CWE-770",
    "CWE-789",
    "CWE-834",
    "CWE-835",
    "CWE-1333",
}
RCE_TEXT = re.compile(
    r"remote code execution|arbitrary code execution|execute arbitrary (code|commands)"
    r"|command injection|code injection",
    re.I,
)
DOS_TEXT = re.compile(
    r"denial of service|infinite loop|resource exhaustion|\bcrash", re.I
)

# Availability-only impact, CVSS v3 (C:N/I:N/A:H) or v4 (VC:N/VI:N/VA:H)
DOS_VECTOR = re.compile(r"\bV?C:N/V?I:N/V?A:[LH]\b")


@dataclass
class Finding:
    id: str
    severity: str
    pkg: str
    version: str
    fix: str
    url: str
    kev: bool = False
    epss: float | None = None
    cls: str = ""  # "RCE", "DoS" or ""
    tier: str = "normal"  # "urgent" or "normal"


def exploit_class(vuln: dict, related: list[dict]) -> str:
    """Rough impact class from CWEs, descriptions and CVSS vectors of the vuln and its NVD entries"""

    entries = [vuln, *related]
    cwes = {c.get("cwe") for e in entries for c in e.get("cwes") or []}
    text = " ".join(e.get("description") or "" for e in entries)
    vectors = [c.get("vector") or "" for e in entries for c in e.get("cvss") or []]

    # Needing privileges (PR:L/H) means it is not remote code execution for an outsider
    scored = [v for v in vectors if v.startswith("CVSS:")]
    unauthenticated = not scored or any("/PR:N/" in v for v in scored)

    if unauthenticated and (cwes & RCE_CWES or RCE_TEXT.search(text)):
        return "RCE"

    if (
        cwes & DOS_CWES
        or DOS_TEXT.search(text)
        or any(DOS_VECTOR.search(v) for v in vectors)
    ):
        return "DoS"

    return ""


class Scanner:
    def __init__(self, config: Config) -> None:
        self.config = config
        self._last_db_update = 0.0

    def artifact(self, image_id: str, kind: str) -> Path:
        """Path of a per-image file. kind: syft.json, cdx.json, grype.json, or a .partial temp"""

        directory = (
            self.config.report_dir if kind == "grype.json" else self.config.sbom_dir
        )

        return directory / f"{hex_id(image_id)}.{kind}"

    def artifacts(self, image_id: str) -> list[Path]:
        """Every file stored for an image"""

        h = hex_id(image_id)

        return [
            p
            for d in (self.config.sbom_dir, self.config.report_dir)
            for p in d.glob(f"{h}.*")
        ]

    def has_sbom(self, image_id: str) -> bool:
        return self.artifact(image_id, "syft.json").exists()

    def ensure_db(self, force: bool = False) -> None:
        if (
            not force
            and time.time() - self._last_db_update < self.config.db_update_interval
        ):
            return

        log.info("Updating Grype vulnerability DB")

        try:
            run_tool(["grype", "db", "update"], self.config.db_update_timeout)

            self._last_db_update = time.time()
        except RuntimeError as e:
            log.warning("%s", e)

    def generate_sbom(self, image_id: str, refs: list[str]) -> None:
        """Writes <id>.syft.json and <id>.cdx.json, trying each ref until syft can read the image"""

        out_json, out_cdx = (
            self.artifact(image_id, "syft.json"),
            self.artifact(image_id, "cdx.json"),
        )
        tmp_json, tmp_cdx = (
            self.artifact(image_id, "syft.partial"),
            self.artifact(image_id, "cdx.partial"),
        )
        last_err = ""

        for ref in refs:
            log.info("Generating SBOM for %s", ref)

            try:
                run_tool(
                    [
                        "syft",
                        "scan",
                        "--from",
                        "docker",
                        ref,
                        "-q",
                        "-o",
                        f"syft-json={tmp_json}",
                        "-o",
                        f"cyclonedx-json={tmp_cdx}",
                    ],
                    self.config.syft_timeout,
                )
            except RuntimeError as e:
                last_err = str(e)

                log.debug("ref %s: %s", ref, e)
                continue

            if tmp_json.exists():
                if tmp_cdx.exists():
                    tmp_cdx.replace(out_cdx)

                tmp_json.replace(
                    out_json
                )  # written last: its presence marks the SBOM as complete

                return

            last_err = "syft produced no output"

        tmp_json.unlink(missing_ok=True)
        tmp_cdx.unlink(missing_ok=True)
        raise RuntimeError(
            f"syft could not read image {hex_id(image_id)[:12]}: {last_err}"
        )

    def match(self, sbom: Path, only_fixed: bool) -> str:
        """Raw Grype JSON for an SBOM file"""

        cmd = ["grype", f"sbom:{sbom}", "-o", "json", "-q", "--by-cve"]

        if only_fixed:
            cmd.append("--only-fixed")

        if self.config.grype_config.is_file():
            cmd += ["-c", str(self.config.grype_config)]

        env = {
            **os.environ,
            "GRYPE_DB_AUTO_UPDATE": "false",
        }  # DB is refreshed by ensure_db()

        return run_tool(cmd, self.config.grype_timeout, env=env)

    def grype_scan(self, image_id: str) -> dict:
        """Matches the stored SBOM against the DB; saves and returns the raw report"""

        out = self.match(self.artifact(image_id, "syft.json"), self.config.only_fixed)

        self.artifact(image_id, "grype.json").write_text(out)

        return json.loads(out)


def parse_matches(
    report: dict, min_rank: int, epss_threshold: float, skip_wont_fix: bool = True
) -> tuple[dict[str, Finding], dict, dict[str, Finding]]:
    """Returns (alertable findings keyed by vuln|pkg|version, counts for all severities, the other findings)

    Alertable = at/above min_rank, or urgent at any severity: a known-exploited
    Medium matters more than an unexploited High. Findings the distro won't fix
    (Debian no-dsa/ignored, fix state "wont-fix") are not alertable unless known-exploited or skip_wont_fix is off
    """

    unique: dict = {}

    for m in report.get("matches", []):
        v, a = m.get("vulnerability", {}), m.get("artifact", {})
        sev = (v.get("severity") or "Unknown").capitalize()

        unique.setdefault(f"{v.get('id')}|{a.get('name')}|{a.get('version')}", (sev, m))

    counts = dict(Counter(sev for sev, _ in unique.values()))

    found: dict[str, Finding] = {}
    rest: dict[str, Finding] = {}

    for key, (sev, m) in unique.items():
        v, a = m.get("vulnerability", {}), m.get("artifact", {})
        epss = max((e.get("epss") or 0.0 for e in v.get("epss") or []), default=None)
        f = Finding(
            id=v.get("id"),
            severity=sev,
            pkg=a.get("name"),
            version=a.get("version"),
            fix=", ".join((v.get("fix") or {}).get("versions") or []),
            url=v.get("dataSource", ""),
            kev=bool(v.get("knownExploited")),
            epss=epss,
            cls=exploit_class(v, m.get("relatedVulnerabilities") or []),
        )

        if f.kev or (epss is not None and epss >= epss_threshold) or f.cls == "RCE":
            f.tier = "urgent"

        wont_fix = (
            skip_wont_fix
            and (v.get("fix") or {}).get("state") == "wont-fix"
            and not f.kev
        )
        alertable = f.tier == "urgent" or rank(sev) >= min_rank

        (found if alertable and not wont_fix else rest)[key] = f

    return found, counts, rest
