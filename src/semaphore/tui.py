"""Terminal UI to edit settings (tier rules, rescan schedule and Apprise targets), list scanned images, request rescans,
re-send the last batch and send test alerts


Run inside the container: docker exec -it semaphore semaphore-tui
Talks to the daemon over its socket (bus.py): status pushed for the Images tab and the footer,
rescan requests and "settings saved" sent back. Data is read from semaphore.db
With TUI_RELOAD set (make tui), source edits restart the TUI
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import sqlite3
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import ClassVar

import apprise
from rich.spinner import Spinner
from rich.style import Style
from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
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

from .alerts import TIERS, Alerter, ImageAlert, importance
from .config import SEV_RANK, Config
from .scan import Finding
from .store import State, row_order
from .util import plural, rank

SEVERITIES = list(reversed(SEV_RANK))  # critical first
RELOAD = "reload"  # App.run() result asking main() to restart with fresh code
FRAMES = Spinner("dots").frames
SCANNING = Style(color="black", bgcolor="yellow")
SCANNING_CURSOR = Style(color="black", bgcolor="bright_yellow", bold=True)


def source_mtimes() -> dict[Path, float]:
    return {p: p.stat().st_mtime for p in Path(__file__).parent.glob("*.py")}


class Dropdown(Select, inherit_bindings=False):
    """Select that opens on enter/space only, so arrow keys stay free to move between fields"""

    BINDINGS: ClassVar[list] = [
        Binding("enter,space", "show_overlay", "Open", show=False)
    ]


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


def short_counts(counts: dict) -> str:
    """{"High": 5, "Critical": 3} -> C:3 | H:5"""

    return (
        " | ".join(
            f"{s[0]}:{n}"
            for s, n in sorted(counts.items(), key=lambda kv: -rank(kv[0]))
            if n
        )
        or "clean"
    )


def local_time(iso: str | None) -> str:
    return (
        datetime.fromisoformat(iso).astimezone().strftime("%Y-%m-%d %H:%M")
        if iso
        else "—"
    )


class Confirm(ModalScreen[bool]):
    """Yes/no dialog, Cancel focused first and escape cancels"""

    AUTO_FOCUS = "#no"

    BINDINGS: ClassVar[list] = [("escape", "dismiss(False)", "Cancel")]

    DEFAULT_CSS = """
    Confirm { align: center middle; }
    Confirm > Vertical { width: 70; height: auto; border: thick $error; background: $surface; padding: 1 2; }
    Confirm Horizontal { height: auto; margin-top: 1; }
    """

    def __init__(self, message: str) -> None:
        super().__init__()

        self.message = message

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(self.message)

            with Horizontal():
                yield Button("Discard and rescan", variant="error", id="yes")
                yield Button("Cancel", id="no")

    @on(Button.Pressed)
    def answer(self, event: Button.Pressed) -> None:
        event.stop()
        self.dismiss(event.button.id == "yes")


class Findings(ModalScreen):
    """Every finding of an image's last scan, most severe first. Non-alertable ones dimmed"""

    BINDINGS: ClassVar[list] = [("escape", "dismiss", "Close")]

    DEFAULT_CSS = """
    Findings { align: center middle; }
    Findings > Vertical { width: 90%; height: 80%; border: thick $primary; background: $surface; padding: 1 2; }
    Findings DataTable { height: 1fr; }
    """

    def __init__(
        self, name: str, findings: list[tuple[str, Finding, bool]], update: dict | None
    ) -> None:
        super().__init__()

        self.title_text = f"{name}: {plural(len(findings), 'finding', 'findings')}, {sum(a for *_, a in findings)} alertable"
        self.findings = sorted(
            findings, key=lambda kfa: (-rank(kfa[1].severity), importance(kfa[1]))
        )
        update = update or {}
        self.update_ref = update.get("ref")
        self.fixed = {*update.get("fixes", ()), *update.get("also_fixes", ())}

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(self.title_text)
            yield DataTable(cursor_type="row")

    def on_mount(self) -> None:
        table = self.query_one(DataTable)

        table.add_columns("CVE", "Severity", "Package", "Version", "Fix", "Tags")

        for key, f, alertable in self.findings:
            style = "" if alertable else "dim"
            tags = [
                t
                for t in (
                    "KEV" if f.kev else "",
                    f"EPSS {f.epss:.0%}" if f.epss else "",
                    f.cls,
                    "urgent" if f.tier == "urgent" else "",
                )
                if t
            ]
            cve = Text(f.id or "", style=style)

            if key in self.fixed:
                cve.append(f" (fixed in {self.update_ref})", style="green")

            table.add_row(
                cve,
                *(
                    Text(v or "", style=style)
                    for v in (f.severity, f.pkg, f.version, f.fix, " ".join(tags))
                ),
            )

        table.focus()


class ImageTable(DataTable):
    BINDINGS: ClassVar[list] = [
        Binding("space", "tick", "Tick"),
        Binding("enter", "select_cursor", "Show details"),
    ]

    def action_tick(self) -> None:
        if self.row_count:
            self.app.toggle_image(
                self.coordinate_to_cell_key(self.cursor_coordinate).row_key
            )

    def _get_row_style(self, row_index: int, base_style: Style) -> Style:
        style = super()._get_row_style(row_index, base_style)

        if (
            row_index >= 0
            and self.ordered_rows[row_index].key.value in self.app.scanning
        ):
            return style + SCANNING

        return style

    def _render_cell(
        self, row_index, column_index, base_style, width, cursor=False, hover=False
    ):
        """Keeps a scanning row yellow under the cursor, which would paint over it"""

        if (
            cursor
            and row_index >= 0
            and self.ordered_rows[row_index].key.value in self.app.scanning
        ):
            return super()._render_cell(
                row_index,
                column_index,
                base_style + SCANNING_CURSOR,
                width,
                False,
                hover,
            )

        return super()._render_cell(
            row_index, column_index, base_style, width, cursor, hover
        )


class SemaphoreTUI(App):
    TITLE = "sémaphore"

    BINDINGS: ClassVar[list] = [
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
    #image-table { height: auto; max-height: 24; }
    TabbedContent { height: 1fr; }
    #status { height: 1; padding: 0 1; }
    Button { min-width: 0; height: 1; padding: 0; margin-right: 1; border: none !important; }
    Button:last-child { margin-right: 0; }
    TabPane > Button { margin-top: 1; }
    """

    def __init__(self) -> None:
        super().__init__()

        self.base = Config.from_env()
        self.config = self.base.apply_settings(
            State(self.base.data_dir, readonly=True).settings
        )
        self.last_ctrl_c = 0.0
        self.selected: set[str] = set()  # image ids ticked in the Images tab
        self.scanning: set[str] = set()  # image ids the daemon is scanning or asked to
        self.names: dict[str, str] = {}  # image id -> name shown in the Images tab
        self.rows: list[dict] = []  # rows shown in the Images tab
        self.daemon: dict | None = (
            None  # last status pushed by the daemon, None = not connected
        )
        self.conn: socket.socket | None = None
        self.closing = threading.Event()  # stops listen()
        self.frame = 0

    def compose(self) -> ComposeResult:
        yield Header()

        with TabbedContent():
            with TabPane("Settings", id="tiers"):
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

                with Horizontal(classes="setting"):
                    yield Label(
                        "Rescan schedule: cron expression in the daemon's local time (TZ)"
                    )
                    yield Input(self.config.rescan_schedule, id="schedule")

                yield Button("Save", variant="primary", classes="save")

            with TabPane("Targets", id="targets"):
                yield Label("Define Apprise targets")

                with VerticalScroll(id="target-list"):
                    for url, tiers in self.config.routes():
                        yield TargetRow(url, tiers)

                with Horizontal(classes="target"):
                    yield Button("Add target", id="add")
                    yield Button("Save", variant="primary", classes="save")

            with TabPane("Images", id="images"):
                yield Label("Space ticks an image for rescan, enter shows its CVEs")
                yield ImageTable(id="image-table", cursor_type="row")

                with Horizontal(classes="target"):
                    yield Button(
                        "Rescan selected", variant="warning", id="rescan-selected"
                    )
                    yield Button("Rescan all", variant="error", id="rescan-all")

            with TabPane("Resend", id="resend"):
                yield Static(id="last-batch")

                with Horizontal(classes="target"):
                    yield Button("Re-send", variant="warning", id="resend-btn")
                    yield Button("Refresh", id="refresh")

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

        yield Static(id="status")
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
        table = self.table = self.query_one("#image-table", DataTable)

        table.add_column("✓", key="sel")
        table.add_column("Image", key="name")
        table.add_columns("Scanned", "Findings", "Update", "After update")
        # kept: query_one looks in the active screen, a modal when a status push lands
        self.status_bar = self.query_one("#status", Static)
        self.show_images()
        self.show_status()
        self.show_last_batch()
        self.set_interval(0.08, self.spin)
        self.listen()

        if os.getenv("TUI_RELOAD"):
            self.mtimes = source_mtimes()

            self.set_interval(1, self.reload_if_changed)

    def on_unmount(self) -> None:
        self.closing.set()

        with contextlib.suppress(AttributeError, OSError):  # not connected
            self.conn.shutdown(socket.SHUT_RDWR)  # unblocks listen()

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

        schedule = self.query_one("#schedule", Input).value.strip()

        try:
            Config(rescan_schedule=schedule)
        except SystemExit as e:
            self.notify(str(e), severity="error")

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
            "rescan_schedule": schedule,
            "targets": targets,
        }

        try:
            state = State(self.base.data_dir)
            state.settings = settings

            state.save()
        except sqlite3.OperationalError as e:  # daemon holding the write lock too long
            self.notify(f"Settings not saved: {e}", severity="error")

            return

        self.config = self.base.apply_settings(settings)
        applied = (
            "" if self.tell({"settings": True}) else ", applied when the daemon starts"
        )

        self.notify(
            f"Settings saved{applied}, next rescan {time.ctime(self.config.next_rescan(time.time()))}"
        )

    # ------------------------------------------------------------ images

    @work(thread=True, exclusive=True, group="daemon")
    def listen(self) -> None:
        """Follows the status the daemon pushes, reconnecting while it's down"""

        while not self.closing.is_set():
            try:
                with socket.socket(socket.AF_UNIX) as conn:
                    conn.connect(str(self.base.socket_path))
                    self.conn = conn

                    # settings saved while disconnected, a no-op when unchanged
                    self.tell({"settings": True})

                    for raw in conn.makefile("rb"):
                        self.call_from_thread(self.on_daemon, json.loads(raw))
            except (OSError, ValueError):
                pass

            self.conn = None

            if self.closing.is_set():
                return

            self.call_from_thread(self.on_daemon, None)
            # retries every 2 s only while the daemon is down
            self.closing.wait(2)

    def on_daemon(self, status: dict | None) -> None:
        if status is None and self.daemon is None:
            return

        self.daemon = status

        self.show_images()
        self.show_status()

    def tell(self, msg: dict) -> bool:
        """Sends msg to the daemon, False when it isn't connected"""

        try:
            self.conn.sendall(json.dumps(msg).encode() + b"\n")
        except (AttributeError, OSError):
            return False

        return True

    def show_status(self) -> None:
        a = (self.daemon or {}).get("activity")

        if self.daemon is None:
            text = Text("Daemon not running", style="red")
        elif a is None:
            text = Text("Idle", style="dim")
        else:
            parts = [
                *([a["image"]] if a["image"] else []),
                a["stage"],
                f"{int(time.time() - a['since'])}s",
                *([f"{a['left']} left"] if a["left"] > 1 else []),
            ]
            text = Text(f"{FRAMES[self.frame]} {' · '.join(parts)}")

        self.status_bar.update(text)

    def image_label(self, img_id: str) -> str:
        name = self.names[img_id]

        return f"{FRAMES[self.frame]} {name}" if img_id in self.scanning else name

    def spin(self) -> None:
        table = self.table
        spinning = self.scanning & self.names.keys()
        active = (self.daemon or {}).get("activity")

        if not spinning and not active:
            return

        self.frame = (self.frame + 1) % len(FRAMES)

        if active:
            self.show_status()

        for img_id in spinning:
            table.update_cell(img_id, "name", self.image_label(img_id))

    def show_images(self) -> None:
        table = self.table
        state = State(self.base.data_dir, readonly=True)
        rows = state.rows()
        daemon = self.daemon or {"scanning": [], "pending": []}
        pending = daemon["pending"]
        scanning = {*daemon["scanning"], *(pending or ())}
        in_db = {r["id"] for r in rows}

        # a discarded image leaves the DB until its new scan lands: keep showing its old row meanwhile
        rows += [
            r
            for r in self.rows
            if r["id"] not in in_db and (pending is None or r["id"] in scanning)
        ]

        rows.sort(key=row_order)

        self.rows = rows
        self.names = {r["id"]: r["name"] or r["id"] for r in rows}
        self.selected &= self.names.keys()
        self.scanning = scanning | (self.names.keys() if pending is None else set())
        cursor = (
            table.coordinate_to_cell_key(table.cursor_coordinate).row_key
            if table.row_count
            else None
        )

        table.clear()

        for r in rows:
            u = r["update"]

            table.add_row(
                "✓" if r["id"] in self.selected else "",
                self.image_label(r["id"]),
                local_time(r["last_scan"]),
                short_counts(r["counts"] or {}),
                f"{u['ref']} (fixes {len(u['fixes'])})" if u else "—",
                (short_counts(u["counts"]) if "counts" in u else "?") if u else "",
                key=r["id"],
            )

        if cursor is not None and cursor.value in self.names:
            table.move_cursor(row=table.get_row_index(cursor))

    def toggle_image(self, row_key) -> None:
        img_id = row_key.value
        self.selected ^= {img_id}

        self.table.update_cell(row_key, "sel", "✓" if img_id in self.selected else "")

    @on(DataTable.RowSelected, "#image-table")
    def show_findings(self, event: DataTable.RowSelected) -> None:
        img_id = event.row_key.value
        state = State(self.base.data_dir, readonly=True)

        self.push_screen(
            Findings(
                event.data_table.get_row(event.row_key)[1],
                state.findings(img_id),
                state.update(img_id),
            )
        )

    @on(Button.Pressed, "#rescan-selected")
    def rescan_selected(self) -> None:
        if not self.selected:
            self.notify("Tick images first (space)", severity="warning")

            return

        self.confirm_rescan(sorted(self.selected))

    @on(Button.Pressed, "#rescan-all")
    def rescan_all(self) -> None:
        self.confirm_rescan(None)

    def confirm_rescan(self, ids: list[str] | None) -> None:
        what = "every image" if ids is None else plural(len(ids), "image", "images")

        def done(yes: bool | None) -> None:
            if yes:
                self.request_rescan(ids)

        self.push_screen(
            Confirm(
                f"Discard the SBOMs, scan results and alert history of {what} and rescan from scratch?\n\n"
                "Every current finding will be alerted again."
            ),
            done,
        )

    def request_rescan(self, ids: list[str] | None) -> None:
        """Asks the daemon to rescan, it merges requests it hasn't started yet. None = all images"""

        if not self.tell({"rescan": ids}):
            self.notify("Daemon not running, rescan not requested", severity="error")

            return

        self.selected.clear()
        self.show_images()
        self.notify("Rescan requested")

    # ------------------------------------------------------------ sending

    def show_last_batch(self) -> None:
        batch = State(self.base.data_dir, readonly=True).last_batch
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

    @on(Button.Pressed, "#resend-btn")
    def resend(self) -> None:
        messages = (State(self.base.data_dir, readonly=True).last_batch or {}).get(
            "messages"
        )

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
