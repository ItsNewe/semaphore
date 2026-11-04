"""Finds a newer upstream image (same tag rebuilt, or a newer version tag) and checks which findings it fixes

Registry calls go through crane, the candidate is SBOM'd from the registry (no docker pull) and matched with Grype
"""

from __future__ import annotations

import json
import logging
import re

from .config import Config
from .scan import Finding, Scanner, parse_matches
from .util import hex_id, now_iso, run_tool

log = logging.getLogger("semaphore")

# Optional "v", dotted numbers, then a suffix that must match exactly ("-alpine", "-slim-bookworm")
VERSION_TAG = re.compile(r"^(v?)(\d+(?:\.\d+)*)(.*)$")


def newer_tag(tag: str, tags) -> str | None:
    """Highest tag in the same line as `tag`: same shape, same numbers except the last (1.27.3 -> 1.27.x)

    one candidate per line, no major bumps. Date or odd schemes (bookworm-20250101) get None and
    only the rebuild check applies
    """

    m = VERSION_TAG.match(tag)

    if not m or "." not in m[2]:
        return None  # "latest", or a moving major tag like "3": the rebuild check covers those

    cur = tuple(map(int, m[2].split(".")))

    best: tuple | None = None

    for t in tags:
        c = VERSION_TAG.match(t)

        if not c or (c[1], c[3]) != (m[1], m[3]):
            continue

        n = tuple(map(int, c[2].split(".")))

        if (
            len(n) == len(cur)
            and n[:-1] == cur[:-1]
            and n > cur
            and (best is None or n > best[0])
        ):
            best = (n, t)

    return best[1] if best else None


def split_ref(ref: str) -> tuple[str, str] | None:
    """(repo, tag) of a tag reference, None for digest references"""

    if "@" in ref or ref.startswith("sha256:"):
        return None

    repo, _, tag = ref.rpartition(":")

    if not repo or "/" in tag:  # no tag, or the colon was a registry port
        return ref, "latest"

    return repo, tag


def fixed_by(found: dict[str, Finding], report: dict) -> set[str]:
    """Keys of `found` absent from the candidate's report. Version is ignored, it is what the fix changes"""

    left = {
        (m.get("vulnerability", {}).get("id"), m.get("artifact", {}).get("name"))
        for m in report.get("matches", [])
    }

    return {k for k, f in found.items() if (f.id, f.pkg) not in left}


class UpdateChecker:
    def __init__(self, config: Config, scanner: Scanner) -> None:
        self.config = config
        self.scanner = scanner

    def crane(self, *args: str) -> str:
        return run_tool(["crane", *args], self.config.crane_timeout).strip()

    def candidates(
        self, ref: str, local_digests: set[str]
    ) -> list[tuple[str, str, str]]:
        """(display ref, pullable repo@digest, digest) for the rebuilt tag and the newer tag, if any

        Images never pulled from a registry (no RepoDigests) are skipped
        """

        parts = split_ref(ref)

        if not parts or not local_digests:
            return []

        repo, tag = parts
        out = []
        digest = self.crane("digest", f"{repo}:{tag}")

        if digest not in local_digests:
            out.append((f"{repo}:{tag} (rebuilt)", f"{repo}@{digest}", digest))

        newer = newer_tag(tag, self.crane("ls", repo).split())

        if newer:
            digest = self.crane("digest", f"{repo}:{newer}")

            if digest not in local_digests and all(digest != c[2] for c in out):
                out.append((f"{repo}:{newer}", f"{repo}@{digest}", digest))

        return out

    def scan(self, pull_ref: str, digest: str) -> dict:
        """Grype report of a registry image. Its SBOM is cached per digest, so later DB refreshes only re-match"""

        sbom = self.config.sbom_dir / f"upd-{hex_id(digest)}.syft.json"

        if sbom.exists():
            sbom.touch()  # keeps it from being pruned as unused
        else:
            log.info("Generating SBOM for update candidate %s", pull_ref)

            tmp = sbom.with_suffix(".partial")

            run_tool(
                [
                    "syft",
                    "scan",
                    "--from",
                    "registry",
                    pull_ref,
                    "-q",
                    "-o",
                    f"syft-json={tmp}",
                ],
                self.config.syft_timeout,
            )
            tmp.replace(sbom)

        # Without --only-fixed: an unfixed CVE still present in the candidate must not count as fixed
        return json.loads(self.scanner.match(sbom, only_fixed=False))

    def check(
        self,
        image_id: str,
        refs: list[str],
        found: dict[str, Finding],
        rest: dict[str, Finding] | None = None,
    ) -> dict | None:
        """The candidate fixing the most alertable findings (rebuild wins ties), None if none fixes any

        rest: non-alertable findings, only reported in "also_fixes"

        refs: the image's references, repo@digest ones included. Raises RuntimeError when the registry
        can't be queried, so callers can keep the previous result
        """

        hid = hex_id(image_id)
        ref = next(
            (r for r in refs if split_ref(r) and not hid.startswith(r)), None
        )  # skip (short) image IDs
        digests = {r.split("@", 1)[1] for r in refs if "@" in r}

        if not ref:
            return None

        best = None

        for label, pull, digest in self.candidates(ref, digests):
            try:
                report = self.scan(pull, digest)
                fixes = fixed_by(found, report)
            except (RuntimeError, OSError, ValueError) as e:
                log.warning("Could not scan update candidate %s: %s", pull, e)
                continue

            if fixes and (best is None or len(fixes) > len(best["fixes"])):
                best = {
                    "ref": label,
                    "pull": pull,
                    "digest": digest,
                    "fixes": sorted(fixes),
                    "also_fixes": sorted(fixed_by(rest or {}, report)),
                    "checked": now_iso(),
                    # candidate is matched without --only-fixed, comparable to the image's counts only with ONLY_FIXED off
                    "counts": parse_matches(
                        report,
                        self.config.min_rank,
                        self.config.epss_threshold,
                        self.config.skip_wont_fix,
                        self.config.skip_disputed,
                        self.config.skip_negligible,
                    )[1],
                }

        return best

    def prune(self, since: float) -> None:
        """Deletes candidate SBOMs not used since the previous rescan started, i.e. by the last two rescans"""

        for p in self.config.sbom_dir.glob("upd-*.syft.json"):
            if p.stat().st_mtime < since:
                p.unlink(missing_ok=True)
