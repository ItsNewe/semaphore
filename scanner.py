#!/usr/bin/env python3
"""
semaphore: SBOMs (Syft) + vulnerability matching (Grype) + alerts (Apprise)
for every image that is actually running on this Docker host.

  container `start` event (optionally image `pull`)  -> unseen image? -> SBOM + scan
  every RECONCILE_INTERVAL_SECONDS                    -> catch anything the event stream missed
  every RESCAN_INTERVAL_HOURS                         -> refresh Grype DB, re-match stored SBOMs

SBOMs are generated once per image ID. Vulnerability matching is re-run on the
stored SBOMs, because new CVEs get published for images that never change.
Alerts only cover findings not already reported for that image, batched into one message.
"""
from __future__ import annotations

import json
import logging
import os
import queue
import re
import subprocess
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import apprise
import docker
from docker.errors import DockerException, NotFound


def env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    return default if v is None else v.strip().lower() in ("1", "true", "yes", "on")


def env_hours(name: str, default: float) -> float:
    """Reads an hours setting and returns seconds."""
    return float(os.getenv(name, str(default))) * 3600


DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
SBOM_DIR = DATA_DIR / "sboms"
REPORT_DIR = DATA_DIR / "reports"
STATE_FILE = DATA_DIR / "state.json"
SUMMARY_FILE = DATA_DIR / "summary.json"

APPRISE_URLS = os.getenv("APPRISE_URLS", "").strip()
MIN_SEVERITY = os.getenv("MIN_SEVERITY", "High").strip().lower()
ONLY_FIXED = env_bool("ONLY_FIXED")
SCAN_ON_PULL = env_bool("SCAN_ON_PULL")
NOTIFY_ON_START = env_bool("NOTIFY_ON_START")
PRUNE_REMOVED = env_bool("PRUNE_REMOVED_IMAGES", True)
RESCAN_INTERVAL = env_hours("RESCAN_INTERVAL_HOURS", 24)
RECONCILE_INTERVAL = int(os.getenv("RECONCILE_INTERVAL_SECONDS", "300"))
DB_UPDATE_INTERVAL = env_hours("DB_UPDATE_INTERVAL_HOURS", 6)
MAX_LINES = int(os.getenv("ALERT_MAX_LINES_PER_IMAGE", "10"))
MAX_BODY = int(os.getenv("ALERT_MAX_CHARS", "1800"))
SYFT_TIMEOUT = int(os.getenv("SYFT_TIMEOUT_SECONDS", "1800"))
GRYPE_TIMEOUT = int(os.getenv("GRYPE_TIMEOUT_SECONDS", "600"))
DB_UPDATE_TIMEOUT = 900
GRYPE_CONFIG = Path(os.getenv("GRYPE_CONFIG", "/config/grype.yaml"))
_exclude = os.getenv("EXCLUDE_IMAGES", "").strip()
EXCLUDE = re.compile(_exclude) if _exclude else None

SEV_RANK = {"unknown": 0, "negligible": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}

if MIN_SEVERITY not in SEV_RANK:
    raise SystemExit(f"MIN_SEVERITY must be one of: {', '.join(SEV_RANK)}")

MIN_RANK = SEV_RANK[MIN_SEVERITY]

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)-7s %(message)s",
)
log = logging.getLogger("semaphore")

tasks: "queue.Queue[tuple]" = queue.Queue()
pending_alerts: list[dict] = []
state: dict = {"images": {}, "meta": {}}
_last_db_update = 0.0

notifier = None
if APPRISE_URLS:
    notifier = apprise.Apprise()
    notifier.add(APPRISE_URLS)  # Apprise accepts multiple URLs separated by spaces or commas


# ---------------------------------------------------------------- helpers

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def hex_id(image_id: str) -> str:
    return image_id.split(":", 1)[-1]


def artifact(image_id: str, directory: Path, suffix: str) -> Path:
    """Path of a per-image file, e.g. artifact(id, SBOM_DIR, "syft.json")."""
    return directory / f"{hex_id(image_id)}.{suffix}"


def rank(sev: str) -> int:
    return SEV_RANK.get((sev or "unknown").lower(), 0)


def worst(sevs) -> int:
    """Highest severity rank in an iterable of severity names (0 if empty)."""
    return max((rank(s) for s in sevs), default=0)


def plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def run_tool(cmd: list[str], timeout: int, **kwargs) -> str:
    """Runs a CLI tool and returns its stdout. Raises RuntimeError on failure or timeout."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kwargs)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"{cmd[0]} timed out after {timeout}s") from None
    if r.returncode != 0:
        raise RuntimeError(f"{cmd[0]} failed: {(r.stderr or r.stdout).strip()[-500:]}")
    return r.stdout


def load_state() -> None:
    global state
    if STATE_FILE.exists():
        try:
            state = json.loads(STATE_FILE.read_text())
        except (OSError, ValueError):
            log.warning("state.json unreadable, starting fresh")

    state.setdefault("images", {})
    state.setdefault("meta", {})


def save_state() -> None:
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True))
    tmp.replace(STATE_FILE)


def write_summary() -> None:
    rows = [
        {"image_id": k, **{f: v.get(f) for f in ("name", "containers", "counts", "last_scan")}}
        for k, v in state["images"].items()
    ]
    rows.sort(key=lambda r: (-worst(s for s, n in (r["counts"] or {}).items() if n), r["name"] or ""))
    SUMMARY_FILE.write_text(json.dumps({"generated": now_iso(), "images": rows}, indent=2))


# ---------------------------------------------------------------- docker

def docker_client() -> docker.DockerClient:
    return docker.from_env(timeout=120)


def running_images(client) -> dict:
    """{image_id: {"containers": set[str], "refs": set[str]}} for running containers."""
    out: dict = {}
    for c in client.containers.list(ignore_removed=True):
        img_id = c.attrs.get("Image")
        if not img_id:
            continue

        entry = out.setdefault(img_id, {"containers": set(), "refs": set()})
        entry["containers"].add(c.name)
        ref = (c.attrs.get("Config") or {}).get("Image")
        if ref:
            entry["refs"].add(ref)
    return out


def candidate_refs(client, image_id: str, hints) -> list[str]:
    """References that resolve to exactly this image ID, most readable first.

    A tag may have moved on to a newer image since the container started
    (pulled but not recreated), so each one is checked against the ID.
    """
    try:
        img = client.images.get(image_id)
        tags, digests = img.tags, img.attrs.get("RepoDigests") or []
    except DockerException:
        tags, digests = [], []

    refs: list[str] = []
    for r in list(hints) + list(tags):
        if not r or r in refs or r.startswith("sha256:"):
            continue
        try:
            if client.images.get(r).id == image_id:
                refs.append(r)
        except DockerException:
            pass

    refs += [d for d in digests if d not in refs]
    refs.append(hex_id(image_id))
    return refs


# ---------------------------------------------------------------- syft / grype

def ensure_db(force: bool = False) -> None:
    global _last_db_update
    if not force and time.time() - _last_db_update < DB_UPDATE_INTERVAL:
        return

    log.info("Updating Grype vulnerability DB")
    try:
        run_tool(["grype", "db", "update"], DB_UPDATE_TIMEOUT)
        _last_db_update = time.time()
    except RuntimeError as e:
        log.warning("%s", e)


def generate_sbom(image_id: str, refs: list[str]) -> None:
    """Writes <id>.syft.json and <id>.cdx.json, trying each ref until syft can read the image."""
    out_json, out_cdx = artifact(image_id, SBOM_DIR, "syft.json"), artifact(image_id, SBOM_DIR, "cdx.json")
    tmp_json, tmp_cdx = artifact(image_id, SBOM_DIR, "syft.partial"), artifact(image_id, SBOM_DIR, "cdx.partial")
    last_err = ""
    for ref in refs:
        log.info("Generating SBOM for %s", ref)
        try:
            run_tool(["syft", "scan", "--from", "docker", ref, "-q",
                      "-o", f"syft-json={tmp_json}", "-o", f"cyclonedx-json={tmp_cdx}"], SYFT_TIMEOUT)
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


def grype_scan(sbom: Path) -> dict:
    cmd = ["grype", f"sbom:{sbom}", "-o", "json", "-q", "--by-cve"]
    if ONLY_FIXED:
        cmd.append("--only-fixed")
    if GRYPE_CONFIG.is_file():
        cmd += ["-c", str(GRYPE_CONFIG)]

    env = {**os.environ, "GRYPE_DB_AUTO_UPDATE": "false"}  # DB is refreshed by ensure_db()
    return json.loads(run_tool(cmd, GRYPE_TIMEOUT, env=env))


def parse_matches(report: dict) -> tuple[dict, dict]:
    """Returns (findings at/above MIN_SEVERITY keyed by vuln|pkg|version, counts for all severities)."""
    unique: dict = {}
    for m in report.get("matches", []):
        v, a = m.get("vulnerability", {}), m.get("artifact", {})
        sev = (v.get("severity") or "Unknown").capitalize()
        unique.setdefault(f'{v.get("id")}|{a.get("name")}|{a.get("version")}', (sev, v, a))

    counts = dict(Counter(sev for sev, _, _ in unique.values()))
    found = {
        key: {
            "id": v.get("id"),
            "severity": sev,
            "pkg": a.get("name"),
            "version": a.get("version"),
            "fix": ", ".join((v.get("fix") or {}).get("versions") or []),
            "url": v.get("dataSource", ""),
        }
        for key, (sev, v, a) in unique.items()
        if rank(sev) >= MIN_RANK
    }
    return found, counts


# ---------------------------------------------------------------- core

def process_image(client, image_id: str, info: dict, rescan: bool = False) -> None:
    hid = hex_id(image_id)
    refs = candidate_refs(client, image_id, info.get("refs", ()))
    name = next((r for r in refs if r != hid), f"<untagged {hid[:12]}>")
    if EXCLUDE and any(EXCLUDE.search(r) for r in refs):
        log.debug("Skipping excluded image %s", name)
        return

    sbom = artifact(image_id, SBOM_DIR, "syft.json")
    is_new = not sbom.exists()
    if not is_new and image_id in state["images"] and not rescan:
        return  # already scanned; the periodic rescan handles new CVEs

    if is_new:
        generate_sbom(image_id, refs)

    ensure_db()
    report = grype_scan(sbom)
    artifact(image_id, REPORT_DIR, "grype.json").write_text(json.dumps(report))
    found, counts = parse_matches(report)

    alerted_before = set(state["images"].get(image_id, {}).get("alerted", []))
    new = {k: v for k, v in found.items() if k not in alerted_before}
    containers = sorted(info.get("containers", ()))
    state["images"][image_id] = {
        "name": name,
        "containers": containers,
        "last_scan": now_iso(),
        "counts": counts,
        "alerted": sorted(found),
    }
    log.info("Scanned %s: %s", name, ", ".join(f"{n} {s}" for s, n in counts.items()) or "no vulnerabilities")
    if new:
        pending_alerts.append({"image_id": image_id, "name": name, "containers": containers,
                               "is_new_image": is_new, "new": new})


def prune(client) -> None:
    for img_id in list(state["images"]):
        try:
            client.images.get(img_id)
        except NotFound:
            log.info("Image %s no longer on host, removing its SBOM/report", state["images"][img_id].get("name"))
            state["images"].pop(img_id)
            for d in (SBOM_DIR, REPORT_DIR):
                for p in d.glob(f"{hex_id(img_id)}.*"):
                    p.unlink(missing_ok=True)


def format_alert(batch: list[dict]) -> tuple[str, str]:
    totals = Counter(f["severity"] for item in batch for f in item["new"].values())
    sev_txt = ", ".join(f"{n} {s.lower()}" for s, n in sorted(totals.items(), key=lambda kv: -rank(kv[0])))
    title = (f"{plural(sum(totals.values()), 'new vulnerability', 'new vulnerabilities')} ({sev_txt}) "
             f"in {plural(len(batch), 'image', 'images')}")

    lines: list[str] = []
    for item in sorted(batch, key=lambda i: -worst(f["severity"] for f in i["new"].values())):
        where = ", ".join(item["containers"]) or "not running"
        tag = " · new image" if item["is_new_image"] else ""
        lines.append(f"**{item['name']}** ({where}){tag}")
        findings = sorted(item["new"].values(), key=lambda f: (-rank(f["severity"]), f["id"] or ""))
        for f in findings[:MAX_LINES]:
            fix = f"fix: {f['fix']}" if f["fix"] else "no fix yet"
            lines.append(f"- {f['id']} [{f['severity']}] {f['pkg']} {f['version']} ({fix})")

        if len(findings) > MAX_LINES:
            lines.append(f"- …and {len(findings) - MAX_LINES} more")

        lines.append("")

    body, used = [], 0
    for i, line in enumerate(lines):
        if used + len(line) + 1 > MAX_BODY:
            body.append(f"…truncated ({len(lines) - i} more lines). Full reports: {REPORT_DIR}")
            break
        body.append(line)
        used += len(line) + 1
    return title, "\n".join(body).strip()


def flush_alerts() -> None:
    if not pending_alerts:
        return
    batch = pending_alerts[:]
    pending_alerts.clear()
    title, body = format_alert(batch)
    log.warning("%s\n%s", title, body)
    if notifier is None:
        return
    if not notifier.notify(title=title, body=body, body_format=apprise.NotifyFormat.MARKDOWN):
        log.error("Notification failed; these findings will be re-alerted on the next rescan")
        for item in batch:
            img = state["images"].get(item["image_id"])
            if img:
                img["alerted"] = sorted(set(img["alerted"]) - set(item["new"]))


def safe(fn, *args, **kwargs) -> None:
    try:
        fn(*args, **kwargs)
    except Exception as e:  # one bad image must not stop the batch
        log.error("%s", e)
        log.debug("details", exc_info=True)


def scan_running(client, rescan: bool = False) -> None:
    for img_id, info in running_images(client).items():
        safe(process_image, client, img_id, info, rescan=rescan)


def handle(client, task: tuple) -> None:
    kind = task[0]
    if kind == "reconcile":
        scan_running(client)
    elif kind == "rescan":
        log.info("Periodic rescan of all running images")
        ensure_db(force=True)
        scan_running(client, rescan=True)
        if PRUNE_REMOVED:
            prune(client)
        state["meta"]["last_rescan"] = time.time()
    elif kind == "image":
        _, img_id, hint = task
        info = running_images(client).get(img_id) or {"containers": set(), "refs": {hint} if hint else set()}
        process_image(client, img_id, info)


def end_of_batch() -> None:
    """Runs once the queue is drained: send alerts, then persist (after any alert rollback)."""
    flush_alerts()
    save_state()
    write_summary()


def worker() -> None:
    client = docker_client()
    while True:
        safe(handle, client, tasks.get())
        if tasks.empty():
            safe(end_of_batch)


def watch_events() -> None:
    types, events = ["container"], ["start"]
    if SCAN_ON_PULL:
        types.append("image")
        events.append("pull")
    while True:
        try:
            client = docker_client()
            log.info("Listening for Docker events: %s", ", ".join(f"{t} {e}" for t, e in zip(types, events)))
            for ev in client.events(decode=True, filters={"type": types, "event": events}):
                actor = ev.get("Actor") or {}
                ref = (actor.get("Attributes") or {}).get("image") or actor.get("ID")
                try:
                    if ev.get("Type") == "container":
                        img_id = client.containers.get(ev["id"]).attrs["Image"]
                    else:
                        img_id = client.images.get(ev["id"]).id
                except (NotFound, KeyError):
                    continue
                tasks.put(("image", img_id, ref))
            log.info("Event stream closed, reconnecting")
        except Exception as e:
            log.warning("Event stream error (%s), reconnecting in 5s", e)
        time.sleep(5)


def scheduler() -> None:
    """Queues a reconcile every RECONCILE_INTERVAL and a rescan when one is due.
    The rescan check runs before the first sleep, so an overdue rescan starts right away."""
    next_rescan = state["meta"]["last_rescan"] + RESCAN_INTERVAL
    while True:
        if time.time() >= next_rescan:
            tasks.put(("rescan",))
            next_rescan = time.time() + RESCAN_INTERVAL
        time.sleep(RECONCILE_INTERVAL)
        tasks.put(("reconcile",))


def main() -> None:
    for d in (SBOM_DIR, REPORT_DIR):
        d.mkdir(parents=True, exist_ok=True)

    load_state()
    log.info("semaphore starting: min severity=%s, only fixed=%s, rescan every %.0fh, pull events=%s",
             MIN_SEVERITY, ONLY_FIXED, RESCAN_INTERVAL / 3600, SCAN_ON_PULL)
    
    if notifier is None:
        log.warning("APPRISE_URLS is not set: alerts will only be written to the log")

    elif NOTIFY_ON_START:
        notifier.notify(title="semaphore started", body="Watching running containers for vulnerabilities")

    ensure_db(force=True)
    state["meta"].setdefault("last_rescan", time.time())  # first boot: initial scan is fresh anyway
    save_state()

    tasks.put(("reconcile",))
    threading.Thread(target=watch_events, daemon=True).start()
    threading.Thread(target=scheduler, daemon=True).start()
    worker()


if __name__ == "__main__":
    main()
