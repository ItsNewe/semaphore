"""
semaphore: SBOMs (Syft) + vulnerability matching (Grype) + alerts (Apprise)
for every image that is actually running on this Docker host

  container `start` event (optionally image `pull`)  -> unseen image? -> SBOM + scan
  every RECONCILE_INTERVAL_SECONDS                    -> catch anything the event stream missed
  on RESCAN_SCHEDULE (cron)                           -> refresh Grype DB, re-match stored SBOMs
  rescan request from the TUI (bus.py socket)         -> regenerate SBOMs + rescan, alert marks kept

Vulnerable images also get an update check on each scan: is the same tag rebuilt upstream, or is there
a newer version tag, and which findings would it fix (updates.py)

SBOMs are generated once per image ID. Vulnerability matching is re-run on the
stored SBOMs, because new CVEs get published for images that never change

Alerts only cover findings not yet reported for that image or escalated to urgent since
They're batched into one message per tier: urgent (KEV, EPSS >= threshold, likely RCE) and normal

Threads: the event watcher, the scheduler and the TUI socket (bus.py) only enqueue tasks; the worker
thread is the only one touching State and Alerter, so no locking is needed. The worker hands the
SBOM + matching + update check of up to SCAN_WORKERS images to a thread pool and commits each result
itself. The worker pushes its status (images being scanned, current stage) to the TUI through the socket
"""

from __future__ import annotations

import logging
import os
import queue
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from .alerts import Alerter, ImageAlert
from .bus import Bus
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
            config  # env only, the TUI settings are re-applied on top when they change
        )
        self.state = State(config.data_dir)
        self.settings = self.state.settings
        self.config = config.apply_settings(self.settings)
        self.scanner = Scanner(config)
        self.updates = UpdateChecker(config, self.scanner)
        self.alerter = Alerter(self.config)
        self.tasks: queue.Queue[tuple] = queue.Queue()
        self.scanning: set[str] = set()  # images left in the batch, pushed to the TUI
        self.bus = Bus(config.socket_path, self.tasks)

        # Runs Semaphore.analyze: syft/grype/crane subprocesses, nothing touching State
        self.pool = ThreadPoolExecutor(config.scan_workers, thread_name_prefix="scan")
        self.host: DockerHost | None = (
            None  # created in run(), used by the worker thread only
        )

    # ------------------------------------------------------------ core

    def prepare(self, image_id: str, info: dict, rescan: bool) -> tuple | None:
        """(image_id, info, refs, name, is_new) of an image to scan, None if excluded or already scanned"""

        hid = hex_id(image_id)
        refs = self.host.candidate_refs(image_id, info.get("refs", ()))
        name = next((r for r in refs if r != hid), f"<untagged {hid[:12]}>")

        if self.config.exclude and any(self.config.exclude.search(r) for r in refs):
            log.debug("Skipping excluded image %s", name)

            return None

        is_new = not self.scanner.has_sbom(image_id)

        if not is_new and image_id in self.state and not rescan:
            return None  # already scanned; the periodic rescan handles new CVEs

        return image_id, info, refs, name, is_new

    def analyze(
        self, image_id: str, info: dict, refs: list[str], name: str, is_new: bool
    ) -> tuple:
        """SBOM, matching and update check. Runs in the scan pool: no State, Alerter or DockerHost here
        Returns (found, counts, rest, update), update is False when the check failed (keep the last result)"""

        if is_new:
            self.status("generating SBOM", name)
            self.scanner.generate_sbom(image_id, refs)

        self.status("matching vulnerabilities", name)

        found, counts, rest = parse_matches(
            self.scanner.grype_scan(image_id),
            self.config.min_rank,
            self.config.epss_threshold,
            self.config.skip_wont_fix,
            self.config.skip_disputed,
            self.config.skip_negligible,
        )
        update = None

        if found and self.config.check_updates:
            # Configured refs first: their tag may have moved to a newer pull since this container started
            self.status("checking updates", name)

            try:
                update = self.updates.check(
                    image_id, [*sorted(info.get("refs", ())), *refs], found, rest
                )
            except RuntimeError as e:
                log.warning("Update check failed for %s: %s", name, e)

                update = False

        return found, counts, rest, update

    def commit(self, job: tuple, result: tuple) -> None:
        """Stores a scan and queues its alerts, on the worker thread"""

        image_id, info, _, name, _ = job
        found, counts, rest, update = result

        if update is False:
            update = self.state.update(image_id)  # keep the last known result

        before = self.state.alerted(image_id)

        # not "no SBOM": a TUI rescan regenerates it but the image isn't new
        first = image_id not in self.state
        new = self.state.new_findings(image_id, found)
        containers = sorted(info.get("containers", ()))

        self.state.record_scan(image_id, name, containers, counts, found, update, rest)
        self.scanning.discard(image_id)
        self.state.save()

        # TUI reloads the committed scan
        self.bus.publish(scanning=sorted(self.scanning))

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
                    first,
                    new,
                    {k: before.get(k) for k in new},
                    update,
                )
            )

        if update and update["notified"] != update["digest"]:
            self.alerter.add_update(image_id, name, containers, update, found)

    def scan_images(self, images: dict, rescan: bool = False) -> None:
        """Scans {image_id: info} up to scan_workers at a time, commits each as it finishes
        One image failing doesn't stop the others"""

        jobs = []

        for img_id, info in images.items():
            try:
                if job := self.prepare(img_id, info, rescan):
                    jobs.append(job)
            except Exception as e:
                log.error("%s", e)
                log.debug("details", exc_info=True)

        if not jobs:
            return

        self.mark_scanning(j[0] for j in jobs)
        self.scanner.ensure_db()

        futures = {self.pool.submit(self.analyze, *job): job for job in jobs}

        for f in as_completed(futures):
            safe(lambda f=f: self.commit(futures[f], f.result()))

    def process_image(self, image_id: str, info: dict, rescan: bool = False) -> None:
        self.scan_images({image_id: info}, rescan)

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
        """Deletes SBOMs and rescans the running images from scratch. Their alert marks stay, so only new or
        escalated findings alert. Stored images not running are forgotten. ids None = every image"""

        running = self.host.running_images()
        targets = set(self.state.ids()) | set(running) if ids is None else ids

        log.info("Discarding the scans of %d image(s), rescanning them", len(targets))
        self.mark_scanning(i for i in targets if i in running)

        for img_id in targets:
            if img_id not in running:
                self.state.forget(img_id)
                self.state.save()  # don't hold the write lock through the SBOM generation

            for p in self.scanner.artifacts(img_id):
                p.unlink(missing_ok=True)

        self.scan_images({i: running[i] for i in targets if i in running})

    def scan_running(self, rescan: bool = False) -> None:
        running = self.host.running_images()

        if rescan:
            self.mark_scanning(running)

        self.scan_images(running, rescan)

    def handle(self, task: tuple) -> None:
        kind = task[0]

        if kind == "reconcile":
            self.scan_running()
        elif kind == "rescan":
            log.info("Periodic rescan of all running images")

            started = time.time()

            self.status("updating vulnerability DB")
            self.scanner.ensure_db(force=True)
            self.scan_running(rescan=True)

            if self.config.prune_removed:
                self.prune()

            self.updates.prune(self.state.last_rescan)

            self.state.last_rescan = started
        elif kind == "discard":
            self.discard(self.bus.take_pending())
        elif kind == "settings":
            self.reload_settings()
        elif kind == "image":
            # Takes the image tasks queued behind this one too (compose up), so they scan in parallel
            hints, later = {task[1]: task[2]}, []

            while True:
                try:
                    t = self.tasks.get_nowait()
                except queue.Empty:
                    break

                if t[0] == "image":
                    hints.setdefault(t[1], t[2])
                else:
                    later.append(t)

            for t in later:
                self.tasks.put(t)

            running = self.host.running_images()

            self.scan_images(
                {
                    i: running.get(i)
                    or {"containers": set(), "refs": {hint} if hint else set()}
                    for i, hint in hints.items()
                }
            )

    def end_of_batch(self) -> None:
        """Runs once the queue is drained: send alerts, then persist (after any alert rollback)"""

        if self.alerter.pending or self.alerter.updates:
            self.status("sending alerts")

        self.alerter.flush(self.state)
        self.scanning.clear()  # left: images whose scan failed
        self.state.save()
        self.state.write_summary()
        self.bus.publish(scanning=[], activity=None)

    def mark_scanning(self, ids) -> None:
        """Adds ids to the images being scanned, shown by the TUI"""

        ids = set(ids)

        if ids <= self.scanning:
            return

        self.scanning |= ids

        self.bus.publish(scanning=sorted(self.scanning))

    def status(self, stage: str, image: str | None = None) -> None:
        """What the daemon is doing, shown in the TUI footer until the batch ends"""

        self.bus.publish(
            activity={
                "stage": stage,
                "image": image,
                "since": time.time(),
                "left": len(self.scanning),
            }
        )

    def reload_settings(self) -> None:
        """Re-applies the settings when the TUI changed them"""

        settings = self.state.settings

        if settings == self.settings:
            return

        self.settings = settings
        self.config = self.base.apply_settings(settings)

        self.alerter.configure(self.config)
        log.info(
            "Settings reloaded: min severity=%s, urgent at EPSS>=%s, rescan schedule '%s', "
            "%d notification target(s)",
            self.config.min_severity,
            self.config.epss_threshold,
            self.config.rescan_schedule,
            len(self.config.routes()),
        )

    # ------------------------------------------------------------ threads

    def worker(self) -> None:
        while True:
            task = self.tasks.get()

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

    def scheduler(self, last_rescan: float) -> None:
        """Queues a reconcile every reconcile_interval and a rescan when one is due
        The rescan check runs before the first sleep, so an overdue rescan starts right away
        last_rescan is passed in: the State connection belongs to the worker thread
        The due time is recomputed each loop, so a schedule changed in the TUI applies without restart"""

        while True:
            if time.time() >= self.config.next_rescan(last_rescan):
                self.tasks.put(("rescan",))

                last_rescan = time.time()

            # checked every reconcile_interval, so a rescan starts up to that late
            time.sleep(self.config.reconcile_interval)
            self.tasks.put(("reconcile",))

    def run(self) -> None:
        cfg = self.config

        for d in (cfg.sbom_dir, cfg.report_dir):
            d.mkdir(parents=True, exist_ok=True)

        log.info(
            "semaphore starting: min severity=%s, urgent at EPSS>=%s/KEV/RCE, only fixed=%s, "
            "skip won't-fix=%s disputed=%s negligible=%s, rescan schedule '%s' (next %s), pull events=%s",
            cfg.min_severity,
            cfg.epss_threshold,
            cfg.only_fixed,
            cfg.skip_wont_fix,
            cfg.skip_disputed,
            cfg.skip_negligible,
            cfg.rescan_schedule,
            time.ctime(cfg.next_rescan(time.time())),
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

        self.bus.start()
        self.status("updating vulnerability DB")
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
        self.worker()


def main() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)-7s %(message)s",
    )
    Semaphore(Config.from_env()).run()
