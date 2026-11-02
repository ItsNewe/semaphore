"""Batches new findings into Apprise notifications"""
from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass

import apprise

from .config import Config
from .scan import Finding
from .store import State
from .util import plural, rank, worst

log = logging.getLogger("semaphore")


@dataclass
class ImageAlert:
    image_id: str
    name: str
    containers: list[str]
    is_new_image: bool
    new: dict[str, Finding]


class Alerter:
    def __init__(self, config: Config, notifier: apprise.Apprise | None = None) -> None:
        self.config = config
        self.pending: list[ImageAlert] = []
        self.notifier = notifier
        if notifier is None and config.apprise_urls:
            self.notifier = apprise.Apprise()
            self.notifier.add(config.apprise_urls)  # Apprise accepts multiple URLs separated by spaces or commas

    def add(self, alert: ImageAlert) -> None:
        self.pending.append(alert)

    def notify_started(self) -> None:
        if self.notifier is not None:
            self.notifier.notify(title="semaphore started", body="Watching running containers for vulnerabilities")

    def format(self, batch: list[ImageAlert]) -> tuple[str, str]:
        max_lines, max_body = self.config.max_lines, self.config.max_body
        totals = Counter(f.severity for item in batch for f in item.new.values())
        sev_txt = ", ".join(f"{n} {s.lower()}" for s, n in sorted(totals.items(), key=lambda kv: -rank(kv[0])))
        title = (f"{plural(sum(totals.values()), 'new vulnerability', 'new vulnerabilities')} ({sev_txt}) "
                 f"in {plural(len(batch), 'image', 'images')}")

        lines: list[str] = []
        for item in sorted(batch, key=lambda i: -worst(f.severity for f in i.new.values())):
            where = ", ".join(item.containers) or "not running"
            tag = " · new image" if item.is_new_image else ""
            lines.append(f"**{item.name}** ({where}){tag}")
            findings = sorted(item.new.values(), key=lambda f: (-rank(f.severity), f.id or ""))
            for f in findings[:max_lines]:
                fix = f"fix: {f.fix}" if f.fix else "no fix yet"
                lines.append(f"- {f.id} [{f.severity}] {f.pkg} {f.version} ({fix})")

            if len(findings) > max_lines:
                lines.append(f"- …and {len(findings) - max_lines} more")

            lines.append("")

        body, used = [], 0
        for i, line in enumerate(lines):
            if used + len(line) + 1 > max_body:
                body.append(f"…truncated ({len(lines) - i} more lines). Full reports: {self.config.report_dir}")
                break
            body.append(line)
            used += len(line) + 1
        return title, "\n".join(body).strip()

    def flush(self, state: State) -> None:
        """Sends everything pending as one message; on failure un-marks it in state for a later retry"""
        if not self.pending:
            return
        batch, self.pending = self.pending, []
        title, body = self.format(batch)
        log.warning("%s\n%s", title, body)
        if self.notifier is None:
            return
        if not self.notifier.notify(title=title, body=body, body_format=apprise.NotifyFormat.MARKDOWN):
            log.error("Notification failed; these findings will be re-alerted on the next rescan")
            for item in batch:
                state.rollback(item.image_id, item.new)
