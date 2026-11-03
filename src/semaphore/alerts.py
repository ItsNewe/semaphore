"""Batches new findings into Apprise notifications, one message per tier

Routing uses Apprise tags "urgent" and "normal", one per tier (see Config.routes)
Fixing-update notices (see updates.py) go out as one more message, tagged "normal"
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field

import apprise

from .config import Config
from .scan import Finding
from .store import State
from .util import now_iso, plural, rank, worst

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
    previous: dict[str, str | None] = field(
        default_factory=dict
    )  # alerted tier before this scan
    update: dict | None = None  # best fixing candidate, see UpdateChecker.check

    def only(self, tier: str) -> ImageAlert | None:
        """This alert restricted to one tier's findings (None if it has none)"""

        new = {k: f for k, f in self.new.items() if f.tier == tier}

        if not new:
            return None

        return ImageAlert(
            self.image_id,
            self.name,
            self.containers,
            self.is_new_image,
            new,
            {k: self.previous.get(k) for k in new},
            self.update,
        )

    @property
    def fixed(self) -> set[str]:
        """Keys of the new findings the update fixes"""

        return set(self.update["fixes"]) & self.new.keys() if self.update else set()


def link(f: Finding) -> str:
    """Markdown link to the advisory: NVD for CVEs (short URL), else Grype's data source"""

    url = (
        f"https://nvd.nist.gov/vuln/detail/{f.id}"
        if (f.id or "").startswith("CVE-")
        else f.url
    )

    return f"[{f.id}]({url})" if url else f.id


def merge(fs: list[Finding]) -> Finding:
    """One finding per vuln id: packages joined, worst severity and EPSS, any KEV"""

    versions = {f.version for f in fs}
    pkgs = (
        sorted({f.pkg for f in fs})
        if len(versions) == 1
        else sorted({f"{f.pkg} {f.version}" for f in fs})
    )
    epss = [f.epss for f in fs if f.epss is not None]

    return Finding(
        id=fs[0].id,
        severity=max((f.severity for f in fs), key=rank),
        pkg=", ".join(pkgs),
        version=versions.pop() if len(versions) == 1 else "",
        fix=", ".join(dict.fromkeys(f.fix for f in fs if f.fix)),
        url=fs[0].url,
        kev=any(f.kev for f in fs),
        epss=max(epss, default=None),
        cls="RCE"
        if any(f.cls == "RCE" for f in fs)
        else next((f.cls for f in fs if f.cls), ""),
        tier=max((f.tier for f in fs), key=lambda t: t == "urgent"),
    )


def importance(f: Finding) -> tuple:
    """Sort key, most important first: KEV, RCE, severity, EPSS"""

    return -bool(f.kev), -(f.cls == "RCE"), -rank(f.severity), -(f.epss or 0), f.id or ""


def describe(f: Finding, escalated: bool, fixed: bool = False) -> str:
    fix = f" (fix: {f.fix})" if f.fix else ""
    tags = [
        t
        for t in (
            "KEV" if f.kev else "",
            f"EPSS {f.epss:.0%}" if f.epss is not None and f.epss >= 0.01 else "",
            f.cls,
            "escalated" if escalated else "",
            "⬆ fixed" if fixed else "",
        )
        if t
    ]

    return (
        f"- {link(f)} [{f.severity}] {f.pkg} {f.version}".rstrip()
        + fix
        + "".join(f" · {t}" for t in tags)
    )


def summary(vulns: list[Finding]) -> str:
    """Critical: x | High: y | RCE: n | KEV: n"""

    sevs = Counter(f.severity for f in vulns)
    parts = [f"{s}: {n}" for s, n in sorted(sevs.items(), key=lambda kv: -rank(kv[0]))]
    rce, kev = sum(f.cls == "RCE" for f in vulns), sum(f.kev for f in vulns)
    parts += [f"{label}: {n}" for label, n in (("RCE", rce), ("KEV", kev)) if n]

    return " | ".join(parts)


class Alerter:
    def __init__(self, config: Config, notifier: apprise.Apprise | None = None) -> None:
        self.pending: list[ImageAlert] = []
        self.updates: list[tuple[str, str]] = []  # (image_id, notice line)
        self.config = config
        self.notifier = notifier

        if notifier is None:
            self.configure(config)

    def configure(self, config: Config) -> None:
        """Applies a new config and rebuilds the notifier from its routes. Pending alerts are kept"""

        self.config = config
        self.notifier = None
        routes = config.routes()

        if routes:
            self.notifier = apprise.Apprise()

            for (
                urls,
                tiers,
            ) in routes:  # Apprise accepts multiple URLs separated by spaces or commas
                self.notifier.add(urls, tag=list(tiers))

    def add(self, alert: ImageAlert) -> None:
        self.pending.append(alert)

    def add_update(
        self,
        image_id: str,
        name: str,
        containers: list[str],
        update: dict,
        found: dict[str, Finding],
    ) -> None:
        """Queues a notice for a fixing update not announced yet"""

        fixes = set(update["fixes"]) & found.keys()
        urgent = sum(found[k].tier == "urgent" for k in fixes)
        where = ", ".join(containers) or "not running"

        self.updates.append(
            (
                image_id,
                f"**{name}** ({where}) → {update['ref']}: fixes {len(fixes)}/{len(found)}"
                + (f" ({urgent} urgent)" if urgent else ""),
            )
        )

    def notify_started(self) -> None:
        if self.notifier is not None:
            self.notifier.notify(
                title="semaphore started",
                body="Watching running containers for vulnerabilities",
            )

    def format(self, batch: list[ImageAlert], prefix: str = "") -> tuple[str, str]:
        max_lines = self.config.max_lines
        grouped = []  # (item, [(merged finding, escalated, fixed)]) with one entry per vuln id

        for item in batch:
            by_id: dict[str, list[str]] = {}

            for k, f in item.new.items():
                by_id.setdefault(f.id or k, []).append(k)

            fixed = item.fixed
            vulns = [
                (
                    merge([item.new[k] for k in keys]),
                    any(item.previous.get(k) is not None for k in keys),
                    any(k in fixed for k in keys),
                )
                for keys in by_id.values()
            ]

            grouped.append((item, sorted(vulns, key=lambda v: importance(v[0]))))

        totals = Counter(v[0].severity for _, vulns in grouped for v in vulns)
        sev_txt = ", ".join(
            f"{n} {s.lower()}"
            for s, n in sorted(totals.items(), key=lambda kv: -rank(kv[0]))
        )
        title = (
            f"{prefix}{plural(sum(totals.values()), 'new vulnerability', 'new vulnerabilities')} ({sev_txt}) "
            f"in {plural(len(batch), 'image', 'images')}"
        )

        lines: list[str] = []

        for item, vulns in sorted(
            grouped, key=lambda g: -worst(v[0].severity for v in g[1])
        ):
            where = ", ".join(item.containers) or "not running"
            tag = " · new image" if item.is_new_image else ""

            lines.append(f"**{item.name}** ({where}){tag}")
            lines.append(summary([v[0] for v in vulns]))

            fixed = item.fixed

            if fixed:
                lines.append(
                    f"⬆ {item.update['ref']} fixes {len(fixed)}/{len(item.new)}"
                )

            for f, escalated, is_fixed in vulns[:max_lines]:
                lines.append(describe(f, escalated, is_fixed))

            if len(vulns) > max_lines:
                lines.append(f"- …and {len(vulns) - max_lines} more")

            lines.append("")

        return title, self.cap(lines)

    def cap(self, lines: list[str]) -> str:
        """Joins lines, truncated to ALERT_MAX_CHARS"""

        body, used = [], 0

        for i, line in enumerate(lines):
            if used + len(line) + 1 > self.config.max_body:
                body.append(
                    f"…truncated ({len(lines) - i} more lines). Full reports: {self.config.report_dir}"
                )
                break

            body.append(line)

            used += len(line) + 1

        return "\n".join(body).strip()

    def flush(self, state: State) -> None:
        """Sends one message per tier, then the update notices. On failure restores that message's marks
        in state for a later retry"""

        if not self.pending and not self.updates:
            return

        batch, self.pending = self.pending, []
        updates, self.updates = self.updates, []
        messages = []

        for tier, (prefix, _) in TIERS.items():
            items = [a for a in (item.only(tier) for item in batch) if a]

            if not items:
                continue

            title, body = self.format(items, prefix)

            messages.append({"tier": tier, "title": title, "body": body})
            log.warning("%s\n%s", title, body)

            if self.send(tier, title, body) is False:
                log.error(
                    "%s notification failed; these findings will be re-alerted on the next rescan",
                    tier,
                )

                for item in items:
                    state.rollback(item.image_id, item.previous)

        if updates:
            title = (
                f"⬆ {plural(len(updates), 'fixing update', 'fixing updates')} available"
            )
            body = self.cap([line for _, line in updates])

            messages.append({"tier": "normal", "title": title, "body": body})
            log.warning("%s\n%s", title, body)

            if self.send("normal", title, body) is False:
                log.error(
                    "update notification failed; it will be re-sent on the next rescan"
                )
            else:
                for image_id, _ in updates:
                    state.mark_update_notified(image_id)

        state.last_batch = {"sent": now_iso(), "messages": messages}

    def send(self, tier: str, title: str, body: str) -> bool | None:
        """Notifies the targets routed to a tier. None when the tier has no destination (log only)"""

        if self.notifier is None or not any(self.notifier.find(tier)):
            return None

        return self.notifier.notify(
            title=title,
            body=body,
            body_format=apprise.NotifyFormat.MARKDOWN,
            notify_type=TIERS[tier][1],
            tag=tier,
        )
