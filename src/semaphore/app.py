"""
semaphore: SBOMs (Syft) + vulnerability matching (Grype) + alerts (Apprise)
for every image that is actually running on this Docker host

  container `start` event (optionally image `pull`)  -> unseen image? -> SBOM + scan
  every RECONCILE_INTERVAL_SECONDS                    -> catch anything the event stream missed
  every RESCAN_INTERVAL_HOURS                         -> refresh Grype DB, re-match stored SBOMs
  <data_dir>/rescan.json written by the TUI            -> discard scans + alert marks, rescan as new

Vulnerable images also get an update check on each scan: is the same tag rebuilt upstream, or is there
a newer version tag, and which findings would it fix (updates.py)

SBOMs are generated once per image ID. Vulnerability matching is re-run on the
stored SBOMs, because new CVEs get published for images that never change

Alerts only cover findings not yet reported for that image or escalated to urgent since
They're batched into one message per tier: urgent (KEV, EPSS >= threshold, likely RCE) and normal

Threads: the event watcher, the scheduler and the request watcher only enqueue tasks; the worker
thread is the only one touching State and Alerter, so no locking is needed
"""

from __future__ import annotations

import json
import logging
import os
import queue
import threading
import time

from .alerts import Alerter, ImageAlert
from .config import Config
from .host import DockerHost
from .scan import Scanner, parse_matches
from .store import State
from .updates import UpdateChecker
from .util import hex_id, safe

log = logging.getLogger("semaphore")


class Semaphore:
    def __init__(self, config: Config) -> None:
        self.base = (
            config  # env only, settings.json is re-applied on top when it changes
        )
        self.settings_mtime = self.settings_stamp()
        self.config = config.apply_settings()
        self.state = State(config.data_dir)
        self.scanner = Scanner(config)
        self.updates = UpdateChecker(config, self.scanner)
        self.alerter = Alerter(self.config)
        self.tasks: queue.Queue[tuple] = queue.Queue()
        self.host: DockerHost | None = (
            None  # created in run(), used by the worker thread only
        )

    # ------------------------------------------------------------ core

    def process_image(self, image_id: str, info: dict, rescan: bool = False) -> None:
        hid = hex_id(image_id)
        refs = self.host.candidate_refs(image_id, info.get("refs", ()))
        name = next((r for r in refs if r != hid), f"<untagged {hid[:12]}>")

        if self.config.exclude and any(self.config.exclude.search(r) for r in refs):
            log.debug("Skipping excluded image %s", name)

            return

        is_new = not self.scanner.has_sbom(image_id)

        if not is_new and image_id in self.state and not rescan:
            return  # already scanned; the periodic rescan handles new CVEs

        if is_new:
            self.scanner.generate_sbom(image_id, refs)

        self.scanner.ensure_db()

        found, counts, rest = parse_matches(
            self.scanner.grype_scan(image_id),
            self.config.min_rank,
            self.config.epss_threshold,
            self.config.skip_wont_fix,
        )
        update = None

        if found and self.config.check_updates:
            # Configured refs first: their tag may have moved to a newer pull since this container started
            try:
                update = self.updates.check(
                    image_id, [*sorted(info.get("refs", ())), *refs], found, rest
                )
            except RuntimeError as e:
                log.warning("Update check failed for %s: %s", name, e)

                update = self.state.update(image_id)  # keep the last known result

        before = self.state.alerted(image_id)
        new = self.state.new_findings(image_id, found)
        containers = sorted(info.get("containers", ()))

        self.state.record_scan(image_id, name, containers, counts, found, update, rest)

        update = self.state.update(image_id)
        urgent = sum(f.tier == "urgent" for f in found.values())

        log.info(
            "Scanned %s: %s%s",
            name,
            ", ".join(f"{n} {s}" for s, n in counts.items()) or "no vulnerabilities",
            f" ({urgent} urgent)" if urgent else "",
        )

        if update:
            log.info(
                "Update for %s: %s fixes %d/%d",
                name,
                update["ref"],
                len(update["fixes"]),
                len(found),
            )

        if new:
            self.alerter.add(
                ImageAlert(
                    image_id,
                    name,
                    containers,
                    is_new,
                    new,
                    {k: before.get(k) for k in new},
                    update,
                )
            )

        if update and update["notified"] != update["digest"]:
            self.alerter.add_update(image_id, name, containers, update, found)

    def prune(self) -> None:
        for img_id in self.state.ids():
            if self.host.has_image(img_id):
                continue

            log.info(
                "Image %s no longer on host, removing its SBOM/report",
                self.state.forget(img_id),
            )

            for p in self.scanner.artifacts(img_id):
                p.unlink(missing_ok=True)

    def discard(self, ids: list[str] | None) -> None:
        """Forgets scans, SBOMs and alert marks, then rescans the running ones as new. ids None = every image"""

        running = self.host.running_images()
        targets = set(self.state.ids()) | set(running) if ids is None else ids

        log.info("Discarding the scans of %d image(s), rescanning them", len(targets))

        for img_id in targets:
            self.state.forget(img_id)

            for p in self.scanner.artifacts(img_id):
                p.unlink(missing_ok=True)

            if img_id in running:
                safe(self.process_image, img_id, running[img_id])

    def scan_running(self, rescan: bool = False) -> None:
        for img_id, info in self.host.running_images().items():
            safe(self.process_image, img_id, info, rescan=rescan)

    def handle(self, task: tuple) -> None:
        kind = task[0]

        if kind == "reconcile":
            self.scan_running()
        elif kind == "rescan":
            log.info("Periodic rescan of all running images")
            self.scanner.ensure_db(force=True)
            self.scan_running(rescan=True)

            if self.config.prune_removed:
                self.prune()

            self.updates.prune()

            self.state.last_rescan = time.time()
        elif kind == "discard":
            self.discard(task[1])
        elif kind == "image":
            _, img_id, hint = task
            info = self.host.running_images().get(img_id) or {
                "containers": set(),
                "refs": {hint} if hint else set(),
            }

            self.process_image(img_id, info)

    def end_of_batch(self) -> None:
        """Runs once the queue is drained: send alerts, then persist (after any alert rollback)"""

        self.alerter.flush(self.state)
        self.state.save()
        self.state.write_summary()

    def settings_stamp(self) -> float | None:
        try:
            return self.base.settings_path.stat().st_mtime
        except OSError:
            return None

    def reload_settings(self) -> None:
        """Re-applies settings.json when the TUI changed it"""

        stamp = self.settings_stamp()

        if stamp == self.settings_mtime:
            return

        self.settings_mtime = stamp
        self.config = self.base.apply_settings()

        self.alerter.configure(self.config)
        log.info(
            "Settings reloaded: min severity=%s, urgent at EPSS>=%s, %d notification target(s)",
            self.config.min_severity,
            self.config.epss_threshold,
            len(self.config.routes()),
        )

    # ------------------------------------------------------------ threads

    def worker(self) -> None:
        while True:
            task = self.tasks.get()

            safe(self.reload_settings)
            safe(self.handle, task)

            if self.tasks.empty():
                safe(self.end_of_batch)

    def watch_events(self) -> None:
        types, events = ["container"], ["start"]

        if self.config.scan_on_pull:
            types.append("image")
            events.append("pull")

        while True:
            try:
                host = (
                    DockerHost()
                )  # own client: docker-py clients are not shared across threads

                log.info(
                    "Listening for Docker events: %s",
                    ", ".join(f"{t} {e}" for t, e in zip(types, events)),
                )

                for img_id, ref in host.events(types, events):
                    self.tasks.put(("image", img_id, ref))

                log.info("Event stream closed, reconnecting")
            except Exception as e:
                log.warning("Event stream error (%s), reconnecting in 5s", e)

            time.sleep(5)

    def check_requests(self) -> None:
        """Queues a discard task for the TUI's rescan.json. Renamed before reading so a request written meanwhile isn't lost"""

        path = self.base.rescan_path
        taken = path.with_suffix(".taken")

        try:
            path.rename(taken)
        except FileNotFoundError:
            return

        try:
            self.tasks.put(("discard", json.loads(taken.read_text())["images"]))
        except (OSError, ValueError, KeyError, TypeError) as e:
            log.warning("Ignoring rescan request %s: %s", path, e)

        taken.unlink(missing_ok=True)

    def watch_requests(self) -> None:
        while True:
            safe(self.check_requests)
            time.sleep(2)

    def scheduler(self, last_rescan: float) -> None:
        """Queues a reconcile every reconcile_interval and a rescan when one is due
        The rescan check runs before the first sleep, so an overdue rescan starts right away
        last_rescan is passed in: the State connection belongs to the worker thread"""

        next_rescan = last_rescan + self.config.rescan_interval

        while True:
            if time.time() >= next_rescan:
                self.tasks.put(("rescan",))

                next_rescan = time.time() + self.config.rescan_interval

            time.sleep(self.config.reconcile_interval)
            self.tasks.put(("reconcile",))

    def run(self) -> None:
        cfg = self.config

        for d in (cfg.sbom_dir, cfg.report_dir):
            d.mkdir(parents=True, exist_ok=True)

        log.info(
            "semaphore starting: min severity=%s, urgent at EPSS>=%s/KEV/RCE, only fixed=%s, "
            "skip won't-fix=%s, rescan every %.0fh, pull events=%s",
            cfg.min_severity,
            cfg.epss_threshold,
            cfg.only_fixed,
            cfg.skip_wont_fix,
            cfg.rescan_interval / 3600,
            cfg.scan_on_pull,
        )

        if self.alerter.notifier is None:
            log.warning(
                "No notification targets: alerts will only be written to the log"
            )
        elif not any(self.alerter.notifier.find("normal")):
            log.warning(
                "No target gets normal-tier alerts: those will only be written to the log"
            )
        elif cfg.notify_on_start:
            self.alerter.notify_started()

        self.scanner.ensure_db(force=True)

        if self.state.last_rescan is None:
            self.state.last_rescan = (
                time.time()
            )  # first boot: initial scan is fresh anyway

        self.state.save()

        self.host = DockerHost()

        self.tasks.put(("reconcile",))
        threading.Thread(target=self.watch_events, daemon=True).start()
        threading.Thread(
            target=self.scheduler, args=(self.state.last_rescan,), daemon=True
        ).start()
        threading.Thread(target=self.watch_requests, daemon=True).start()
        self.worker()


def main() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)-7s %(message)s",
    )
    Semaphore(Config.from_env()).run()
