"""Terminal UI to edit settings.json (tier rules and Apprise targets), re-send the last batch and send test alerts

Run inside the container: docker exec -it semaphore semaphore-tui
The daemon picks up saved settings before its next task, no restart needed
With TUI_RELOAD set (make tui), source edits restart the TUI
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import apprise
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, VerticalScroll
from textual.widgets import (
    Button,
    Checkbox,
    Footer,
    Header,
    Input,
    Label,
    Select,
    SelectionList,
    Static,
    TabbedContent,
    TabPane,
)

from .alerts import TIERS, Alerter, ImageAlert
from .config import SEV_RANK, Config
from .scan import Finding
from .store import State

SEVERITIES = list(reversed(SEV_RANK))  # critical first
RELOAD = "reload"  # App.run() result asking main() to restart with fresh code


def source_mtimes() -> dict[Path, float]:
    return {p: p.stat().st_mtime for p in Path(__file__).parent.glob("*.py")}


class Dropdown(Select, inherit_bindings=False):
    """Select that opens on enter/space only, so arrow keys stay free to move between fields"""

    BINDINGS = [Binding("enter,space", "show_overlay", "Open", show=False)]


class Checklist(SelectionList):
    """SelectionList whose arrow keys move focus out at the first and last item"""

    def action_cursor_up(self) -> None:
        if self.highlighted in (None, 0):
            self.app.action_focus_previous()
        else:
            super().action_cursor_up()

    def action_cursor_down(self) -> None:
        if self.highlighted is None or self.highlighted >= self.option_count - 1:
            self.app.action_focus_next()
        else:
            super().action_cursor_down()


class TargetRow(Horizontal):
    def __init__(self, url: str = "", tiers=("urgent", "normal")) -> None:
        super().__init__(classes="target")

        self.url, self.tiers = url, tiers

    def compose(self) -> ComposeResult:
        yield Input(
            self.url, placeholder="Apprise URL, e.g. ntfy://topic", classes="url"
        )

        for tier in TIERS:
            yield Checkbox(tier, tier in self.tiers, name=tier)

        yield Button("✕", variant="error", classes="remove")

    def value(self) -> tuple[str, list[str]]:
        return self.query_one(Input).value.strip(), [
            c.name for c in self.query(Checkbox) if c.value
        ]


class SemaphoreTUI(App):
    TITLE = "sémaphore"
    BINDINGS = [
        ("ctrl+s", "save", "Save settings"),
        Binding("ctrl+c", "ctrl_c", show=False, priority=True),
        # Focused widgets that use arrows themselves (Input, tabs, open dropdowns) take precedence
        Binding("down,right", "focus_next", show=False),
        Binding("up,left", "focus_previous", show=False),
    ]
    CSS = """
    TabPane { overflow-y: auto; }
    TabPane > * { margin-bottom: 1; }
    .target { height: auto; }
    .target .url { width: 1fr; }
    .setting { height: auto; margin-bottom: 0; }
    .setting > Label { width: 1fr; height: 3; content-align: left middle; }
    .setting > Dropdown, .setting > Input, .setting > Checklist { width: 28; }
    #test-severities { height: auto; }
    TabPane > Button { margin-top: 1; }
    """

    def __init__(self) -> None:
        super().__init__()

        self.base = Config.from_env()
        self.config = self.base.apply_settings()
        self.last_ctrl_c = 0.0

    def compose(self) -> ComposeResult:
        yield Header()

        with TabbedContent():
            with TabPane("Tiers", id="tiers"):
                with Horizontal(classes="setting"):
                    yield Label("Minimum severity for normal alerts")
                    yield Dropdown(
                        [(s.capitalize(), s) for s in SEVERITIES],
                        value=self.config.min_severity,
                        allow_blank=False,
                        id="min-severity",
                    )

                with Horizontal(classes="setting"):
                    yield Label(
                        "EPSS score (0–1) that makes a finding urgent. Note: KEV and likely RCE always are"
                    )
                    yield Input(
                        str(self.config.epss_threshold), type="number", id="epss"
                    )

                yield Button("Save", variant="primary", classes="save")

            with TabPane("Targets", id="targets"):
                yield Label("Define Apprise targets")

                with VerticalScroll(id="target-list"):
                    for url, tiers in self.config.routes():
                        yield TargetRow(url, tiers)

                with Horizontal(classes="target"):
                    yield Button("Add target", id="add")
                    yield Button("Save", variant="primary", classes="save")

            with TabPane("Resend", id="resend"):
                yield Static(id="last-batch")

                with Horizontal(classes="target"):
                    yield Button("Re-send", variant="warning", id="resend-btn")
                    yield Button("Refresh", id="refresh")

            with TabPane("Updates", id="updates"):
                yield Static(id="update-list")
                yield Button("Refresh", id="refresh-updates")

            with TabPane("Test", id="test"):
                with Horizontal(classes="setting"):
                    yield Label("Severities to send")
                    yield Checklist(
                        *(
                            (s.capitalize(), s, s in ("critical", "high"))
                            for s in SEVERITIES
                        ),
                        id="test-severities",
                    )

                with Horizontal(classes="setting"):
                    yield Label("Tier")
                    yield Dropdown(
                        [(t, t) for t in TIERS],
                        value="normal",
                        allow_blank=False,
                        id="test-tier",
                    )

                yield Button("Send test", variant="primary", id="test-btn")

        yield Footer()

    def action_ctrl_c(self) -> None:
        """Quits on a second press within a second. The first one still copies from a focused input"""

        if time.monotonic() - self.last_ctrl_c < 1:
            self.exit()

            return

        self.last_ctrl_c = time.monotonic()

        if hasattr(self.focused, "action_copy"):
            self.focused.action_copy()

        self.notify("Press ctrl+c again to quit", timeout=1)

    def on_mount(self) -> None:
        self.show_last_batch()
        self.show_updates()

        if os.getenv("TUI_RELOAD"):
            self.mtimes = source_mtimes()

            self.set_interval(1, self.reload_if_changed)

    def reload_if_changed(self) -> None:
        if source_mtimes() != self.mtimes:
            self.exit(RELOAD)

    # ------------------------------------------------------------ settings

    @on(Button.Pressed, "#add")
    def add_target(self) -> None:
        self.query_one("#target-list").mount(TargetRow())

    @on(Button.Pressed, ".remove")
    def remove_target(self, event: Button.Pressed) -> None:
        event.button.parent.remove()

    @on(Button.Pressed, ".save")
    def action_save(self) -> None:
        try:
            epss = float(self.query_one("#epss", Input).value)
        except ValueError:
            epss = -1

        if not 0 <= epss <= 1:
            self.notify("EPSS threshold must be between 0 and 1", severity="error")

            return

        targets = []

        for url, tiers in (row.value() for row in self.query(TargetRow)):
            if not url:
                continue

            if not apprise.Apprise().add(url):
                self.notify(f"Apprise can't parse: {url}", severity="error")

                return

            if not tiers:
                self.notify(
                    f"{url} gets no tier, it will never be notified", severity="warning"
                )

            targets.append({"url": url, "tiers": tiers})

        settings = {
            "min_severity": self.query_one("#min-severity", Select).value,
            "epss_threshold": epss,
            "targets": targets,
        }
        path = self.base.settings_path
        tmp = path.with_suffix(".tmp")

        tmp.write_text(json.dumps(settings, indent=2))
        tmp.replace(path)

        self.config = self.base.apply_settings()

        self.notify(f"Saved {path}")

    # ------------------------------------------------------------ sending

    def show_last_batch(self) -> None:
        state = State(self.base.data_dir)

        state.load()

        batch = state.meta.get("last_batch")
        text = (
            f"Last batch, {batch['sent']}:\n"
            + "\n".join(f"  [{m['tier']}] {m['title']}" for m in batch["messages"])
            if batch and batch.get("messages")
            else "No notification batch recorded yet"
        )

        self.query_one("#last-batch", Static).update(text)

    @on(Button.Pressed, "#refresh")
    def refresh_batch(self) -> None:
        self.show_last_batch()

    @on(Button.Pressed, "#refresh-updates")
    def show_updates(self) -> None:
        state = State(self.base.data_dir)

        state.load()

        lines = [
            f"  {img.get('name')} → {u['ref']}: fixes {len(u['fixes'])} (checked {u['checked']})"
            for img in state.images.values()
            if (u := img.get("update"))
        ]

        self.query_one("#update-list", Static).update(
            "Images with a fixing update:\n" + "\n".join(sorted(lines))
            if lines
            else "No fixing update found for any vulnerable image"
        )

    @on(Button.Pressed, "#resend-btn")
    def resend(self) -> None:
        state = State(self.base.data_dir)

        state.load()

        messages = (state.meta.get("last_batch") or {}).get("messages")

        if not messages:
            self.notify("Nothing to re-send", severity="warning")

            return

        self.send([(m["tier"], m["title"], m["body"]) for m in messages])

    @on(Button.Pressed, "#test-btn")
    def send_test(self) -> None:
        severities = self.query_one("#test-severities", Checklist).selected

        if not severities:
            self.notify("Pick at least one severity", severity="warning")

            return

        tier = self.query_one("#test-tier", Select).value

        self.send([sample_alert(Alerter(self.config), severities, tier)])

    @work(thread=True, exclusive=True)
    def send(self, messages: list[tuple[str, str, str]]) -> None:
        alerter = Alerter(self.config)

        for tier, title, body in messages:
            ok = alerter.send(tier, title, body)

            if ok is None:
                self.call_from_thread(
                    self.notify,
                    f"No saved target gets {tier} alerts",
                    severity="warning",
                )
            elif ok:
                self.call_from_thread(self.notify, f"Sent {tier}: {title}")
            else:
                self.call_from_thread(
                    self.notify,
                    f"Sending {tier} failed, see Apprise logs",
                    severity="error",
                )


def sample_alert(
    alerter: Alerter, severities: list[str], tier: str
) -> tuple[str, str, str]:
    """A fake one-image alert with a finding per severity, formatted like a real one"""

    new = {
        f"test-{s}": Finding(
            id=f"CVE-0000-{i:04d}",
            severity=s.capitalize(),
            pkg="semaphore-test",
            version="0.0.0",
            fix="",
            url="",
            kev=tier == "urgent",
            tier=tier,
        )
        for i, s in enumerate(severities, 1)
    }
    title, body = alerter.format(
        [ImageAlert("sha256:test", "semaphore-test", ["test"], False, new)],
        TIERS[tier][0],
    )

    return tier, f"[TEST] {title}", body


def main() -> None:
    if SemaphoreTUI().run() == RELOAD:
        os.execv(
            sys.executable, [sys.executable, *sys.argv]
        )  # new process imports the edited code
