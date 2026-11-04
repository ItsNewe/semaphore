"""Unix socket between the daemon and the TUI, newline-delimited JSON

daemon -> TUI: the status snapshot, on connect and on every change
  {"scanning": [ids], "pending": [ids] or null (= all), "activity": {stage, image, since, left} or null}
TUI -> daemon: {"rescan": [ids] or null (= all)}, {"settings": true} once saved to semaphore.db

Socket threads never touch State: requests become worker tasks, like every other thread's
"""

from __future__ import annotations

import json
import logging
import queue
import socket
import socketserver
import threading
from pathlib import Path

log = logging.getLogger("semaphore")


def line(msg: dict) -> bytes:
    return json.dumps(msg).encode() + b"\n"


class Bus:
    def __init__(self, path: Path, tasks: queue.Queue) -> None:
        self.path = path
        self.tasks = tasks
        self.status = {"scanning": [], "pending": [], "activity": None}
        self.clients: set[socket.socket] = set()
        self.lock = threading.Lock()

    def start(self) -> None:
        bus = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                with bus.lock:
                    bus.clients.add(self.request)
                    self.request.sendall(line(bus.status))

                try:
                    for raw in self.rfile:
                        bus.receive(json.loads(raw))
                except (OSError, ValueError) as e:
                    log.debug("TUI connection dropped: %s", e)
                finally:
                    with bus.lock:
                        bus.clients.discard(self.request)

        self.path.unlink(missing_ok=True)  # left over by a previous run

        server = socketserver.ThreadingUnixStreamServer(str(self.path), Handler)
        server.daemon_threads = True

        threading.Thread(target=server.serve_forever, daemon=True).start()

    def publish(self, **changes) -> None:
        with self.lock:
            self.status.update(changes)
            self.send()

    def send(self) -> None:
        """Pushes the snapshot to every client. Caller holds the lock"""

        msg = line(self.status)

        for c in list(self.clients):
            try:
                c.sendall(msg)
            except OSError:
                self.clients.discard(c)

    def receive(self, msg: dict) -> None:
        if "rescan" in msg:
            ids = msg["rescan"]

            with self.lock:
                pending = self.status["pending"]
                self.status["pending"] = (
                    None if ids is None or pending is None else sorted({*pending, *ids})
                )

                self.send()

            if (
                pending == []
            ):  # a queued discard takes every request merged in until it runs
                self.tasks.put(("discard",))
        elif msg.get("settings"):
            self.tasks.put(("settings",))

    def take_pending(self) -> list[str] | None:
        """Pops the rescan request, None = every image
        Not pushed: the caller's mark_scanning does, so the TUI never sees the images neither pending nor scanning
        """

        with self.lock:
            pending, self.status["pending"] = self.status["pending"], []

        return pending
