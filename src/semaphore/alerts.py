"""Batches new findings into Apprise notifications, one message per tier

Routing uses Apprise tags: APPRISE_URLS get "normal" (plus "urgent" when no
APPRISE_URLS_URGENT is set), APPRISE_URLS_URGENT get "urgent"
"""
from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field

import apprise

from .config import Config
from .scan import Finding
from .store import State
from .util import plural, rank, worst

log = logging.getLogger("semaphore")

TIERS = {  # tier: (title prefix, Apprise notify type), most urgent first
    "urgent": ("🔴 URGENT: ", apprise.NotifyType.FAILURE),
    "normal": ("", apprise.NotifyType.WARNING),
}


@dataclass
class ImageAlert:
    image_id: str
    name: str
    containers: list[str]
    is_new_image: bool
    new: dict[str, Finding]
    previous: dict[str, str | None] = field(default_factory=dict)  # alerted tier before this scan

    def only(self, tier: str) -> ImageAlert | None:
        """This alert restricted to one tier's findings (None if it has none)"""
        new = {k: f for k, f in self.new.items() if f.tier == tier}
        if not new:
            return None
        return ImageAlert(self.image_id, self.name, self.containers, self.is_new_image, new,
                          {k: self.previous.get(k) for k in new})


def describe(f: Finding, escalated: bool) -> str:
    fix = f"fix: {f.fix}" if f.fix else "no fix yet"
    tags = [t for t in (
        "KEV" if f.kev else "",
        f"EPSS {f.epss:.0%}" if f.epss is not None and f.epss >= 0.01 else "",
        f.cls,
        "escalated" if escalated else "",
    ) if t]
    return f"- {f.id} [{f.severity}] {f.pkg} {f.version} ({fix})" + "".join(f" · {t}" for t in tags)


class Alerter:
    def __init__(self, config: Config, notifier: apprise.Apprise | None = None) -> None:
        self.config = config
        self.pending: list[ImageAlert] = []
        self.notifier = notifier
        if notifier is None and (config.apprise_urls or config.apprise_urls_urgent):
            self.notifier = apprise.Apprise()
            # Apprise accepts multiple URLs separated by spaces or commas
            if config.apprise_urls:
                self.notifier.add(config.apprise_urls,
                                  tag=["normal"] if config.apprise_urls_urgent else ["normal", "urgent"])
            if config.apprise_urls_urgent:
                self.notifier.add(config.apprise_urls_urgent, tag="urgent")

    def add(self, alert: ImageAlert) -> None:
        self.pending.append(alert)

    def notify_started(self) -> None:
        if self.notifier is not None:
            self.notifier.notify(title="semaphore started", body="Watching running containers for vulnerabilities")

    def format(self, batch: list[ImageAlert], prefix: str = "") -> tuple[str, str]:
        max_lines, max_body = self.config.max_lines, self.config.max_body
        totals = Counter(f.severity for item in batch for f in item.new.values())
        sev_txt = ", ".join(f"{n} {s.lower()}" for s, n in sorted(totals.items(), key=lambda kv: -rank(kv[0])))
        title = (f"{prefix}{plural(sum(totals.values()), 'new vulnerability', 'new vulnerabilities')} ({sev_txt}) "
                 f"in {plural(len(batch), 'image', 'images')}")

        lines: list[str] = []
        for item in sorted(batch, key=lambda i: -worst(f.severity for f in i.new.values())):
            where = ", ".join(item.containers) or "not running"
            tag = " · new image" if item.is_new_image else ""
            lines.append(f"**{item.name}** ({where}){tag}")
            findings = sorted(item.new.items(), key=lambda kf: (-rank(kf[1].severity), kf[1].id or ""))
            for k, f in findings[:max_lines]:
                lines.append(describe(f, escalated=item.previous.get(k) is not None))

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
        """Sends one message per tier; on failure restores that tier's marks in state for a later retry"""
        if not self.pending:
            return
        batch, self.pending = self.pending, []
        for tier, (prefix, notify_type) in TIERS.items():
            items = [a for a in (item.only(tier) for item in batch) if a]
            if not items:
                continue
            title, body = self.format(items, prefix)
            log.warning("%s\n%s", title, body)
            if self.notifier is None or not any(self.notifier.find(tier)):
                continue  # no destination for this tier: log only
            if not self.notifier.notify(title=title, body=body, body_format=apprise.NotifyFormat.MARKDOWN,
                                        notify_type=notify_type, tag=tier):
                log.error("%s notification failed; these findings will be re-alerted on the next rescan", tier)
                for item in items:
                    state.rollback(item.image_id, item.previous)
