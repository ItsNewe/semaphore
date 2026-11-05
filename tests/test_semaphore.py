import json
import queue
import socket
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path

import pytest

from semaphore.alerts import Alerter, ImageAlert
from semaphore.config import Config
from semaphore.scan import Finding, exploit_class, parse_matches
from semaphore.store import State

# Trimmed real Grype 0.121 output: httpd:2.4.49 and python:3.8-slim-buster
RAW = (Path(__file__).parent / "grype_sample.json").read_text()
SAMPLE = json.loads(RAW)

# CVE-2023-50387 is "wont-fix" in the real sample; cleared here so it stays the high-EPSS DoS fixture
SAMPLE["matches"][1]["vulnerability"]["fix"]["state"] = ""
KEV, DOS, RCE_MEDIUM, PLAIN = (
    "CVE-2021-42013|httpd|2.4.49",
    "CVE-2023-50387|libsystemd0|241-7~deb10u9",
    "CVE-2023-5752|pip|23.0.1",
    "CVE-2021-39537|libncursesw6|6.1+20181013-2+deb10u3",
)
IMG = "sha256:abc"


def parse(cfg=Config()):
    return parse_matches(SAMPLE, cfg.min_rank, cfg.epss_threshold)[:2]


@pytest.fixture
def sock(monkeypatch):
    """Socket path short enough for AF_UNIX (104 bytes on macOS, pytest's tmp_path can be longer)"""

    path = Path(tempfile.mkdtemp(dir="/tmp")) / "s.sock"

    monkeypatch.setattr(Config, "socket_path", property(lambda self: path))

    return path


async def until(pilot, cond) -> None:
    """Waits for something pushed over the socket to land in the TUI"""

    for _ in range(100):
        if cond():
            return

        await pilot.pause(0.02)

    raise AssertionError("timed out")


def test_parse_matches_tiers():
    found, counts = parse()

    assert counts == {"Critical": 1, "High": 2, "Medium": 2}

    # CVE-2022-4415 (Medium, nothing urgent) is dropped; CVE-2023-5752 (Medium, CWE-77) is kept as urgent
    assert set(found) == {KEV, DOS, PLAIN}
    assert (found[KEV].kev, found[KEV].tier) == (True, "urgent")
    assert (found[DOS].cls, found[DOS].tier) == ("DoS", "urgent")  # EPSS 0.9999
    assert (
        RCE_MEDIUM not in found
    )  # CWE-77 but needs privileges (PR:L): not RCE, so a plain Medium
    assert (found[PLAIN].cls, found[PLAIN].tier) == ("", "normal")

    # Non-alertable ones come back separately, together they cover every counted match
    rest = parse_matches(SAMPLE, Config().min_rank, Config().epss_threshold)[2]

    assert RCE_MEDIUM in rest and not rest.keys() & found.keys()
    assert len(found) + len(rest) == sum(counts.values())


def test_non_alertable_findings_stored_but_never_marked(tmp_path):
    found, counts, rest = parse_matches(
        SAMPLE, Config().min_rank, Config().epss_threshold
    )
    s = State(tmp_path)

    s.record_scan(IMG, "img:1", [], counts, found, rest=rest)

    flags = {k: a for k, _, a in s.findings(IMG)}

    assert flags == {**dict.fromkeys(found, True), **dict.fromkeys(rest, False)}
    assert s.alerted(IMG).keys() == found.keys()
    assert next(f for k, f, _ in s.findings(IMG) if k == RCE_MEDIUM) == rest[RCE_MEDIUM]


def test_wont_fix_dropped_unless_known_exploited():
    found, *_ = parse_matches(json.loads(RAW), 0, 0.1)

    assert {f.id for f in found.values()} == {
        "CVE-2021-42013",
        "CVE-2021-39537",
        "CVE-2023-5752",
    }  # both libsystemd0 CVEs dropped

    kev_wont_fix = json.loads(RAW)
    kev_wont_fix["matches"][0]["vulnerability"]["fix"]["state"] = "wont-fix"

    assert KEV in parse_matches(kev_wont_fix, 0, 0.1)[0]

    assert DOS in parse_matches(json.loads(RAW), 0, 0.1, skip_wont_fix=False)[0]


def test_disputed_and_negligible_skipped_unless_known_exploited():
    report = json.loads(RAW)
    plain = next(
        m for m in report["matches"] if m["vulnerability"]["id"] == "CVE-2021-39537"
    )
    plain["vulnerability"]["description"] = "** DISPUTED ** Some bug"
    report["matches"][1]["vulnerability"]["fix"]["state"] = ""
    report["matches"][1]["vulnerability"]["severity"] = (
        "Negligible"  # DOS, urgent by EPSS
    )
    found, _, rest = parse_matches(report, 0, 0.1)

    assert PLAIN in rest and DOS in rest and KEV in found

    found, *_ = parse_matches(
        report, 0, 0.1, skip_disputed=False, skip_negligible=False
    )

    assert {PLAIN, DOS} <= found.keys()

    report["matches"][0]["vulnerability"]["severity"] = "Negligible"  # KEV still alerts

    assert KEV in parse_matches(report, 0, 0.1)[0]


def test_exploit_class_rce_needs_no_privileges():
    v = {"cwes": [{"cwe": "CWE-77"}]}

    assert exploit_class(v, []) == "RCE"  # no CVSS: trust the CWE
    assert (
        exploit_class(
            {
                **v,
                "cvss": [
                    {"vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H"}
                ],
            },
            [],
        )
        == ""
    )
    assert (
        exploit_class(
            {**v, "cvss": [{"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]},
            [],
        )
        == "RCE"
    )


def test_epss_threshold_is_configurable():
    found, _ = parse(Config(epss_threshold=1.0))

    assert found[DOS].tier == "normal"


def test_exploit_class_dos_from_cvss_vector_only():
    assert (
        exploit_class(
            {"cvss": [{"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}]}, []
        )
        == "DoS"
    )
    assert (
        exploit_class(
            {"cvss": [{"vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H"}]},
            [],
        )
        == "DoS"
    )
    assert (
        exploit_class(
            {"cvss": [{"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}, []
        )
        == ""
    )


def test_state_round_trip_and_uncommitted_batch_is_lost(tmp_path):
    found, counts = parse()
    s = State(tmp_path)

    s.record_scan(IMG, "img:1", ["c1"], counts, found)

    s.last_rescan = 123.0

    s.save()
    s.forget(IMG)  # not committed: a crash mid-batch keeps the last saved state

    s2 = State(tmp_path, readonly=True)

    assert s2.alerted(IMG) == {k: f.tier for k, f in found.items()}
    assert s2.last_rescan == 123.0
    assert s2.rows()[0]["containers"] == ["c1"] and s2.rows()[0]["counts"] == counts

    assert State(tmp_path / "missing", readonly=True).rows() == []


def test_legacy_state_json_is_imported_once(tmp_path):
    (tmp_path / "state.json").write_text(
        json.dumps(
            {
                "images": {IMG: {"name": "img:1", "alerted": [PLAIN]}},
                "meta": {"last_rescan": 5.0},
            }
        )
    )

    s = State(tmp_path)

    assert s.alerted(IMG) == {PLAIN: "normal"} and s.last_rescan == 5.0
    assert (tmp_path / "state.json.imported").exists()
    assert not (tmp_path / "state.json").exists()


def test_scan_log_records_added_and_removed_findings(tmp_path):
    found, counts = parse()
    s = State(tmp_path)
    fewer = {k: f for k, f in found.items() if k != PLAIN}

    s.record_scan(IMG, "img:1", [], counts, found)

    first_seen = s.db.execute("SELECT first_seen FROM findings WHERE key = ?", (KEV,))
    first_seen = first_seen.fetchone()[0]

    s.db.execute("UPDATE findings SET first_seen = 'earlier'")
    s.record_scan(IMG, "img:1", [], counts, fewer)

    log = s.db.execute("SELECT added, removed FROM scans ORDER BY rowid").fetchall()

    assert first_seen
    assert [(json.loads(a), json.loads(r)) for a, r in log] == [
        (sorted(found), []),
        ([], [PLAIN]),
    ]
    assert s.db.execute("SELECT DISTINCT first_seen FROM findings").fetchall() == [
        ("earlier",)
    ]  # carried over


def test_escalation_counts_as_new_but_not_downgrade(tmp_path):
    found, counts = parse()
    s = State(tmp_path)

    s.record_scan(IMG, "img:1", [], counts, found)
    s.db.execute("UPDATE findings SET alerted = 'normal'")
    assert set(s.new_findings(IMG, found)) == {KEV, DOS}  # escalated to urgent
    s.record_scan(IMG, "img:1", [], counts, found)

    calmer, _ = parse(Config(epss_threshold=1.0))  # DOS drops back to normal

    s.record_scan(IMG, "img:1", [], counts, calmer)
    assert (
        s.alerted(IMG)[DOS] == "urgent"
    )  # tiers only go up: no re-alert if EPSS rises again
    assert s.new_findings(IMG, found) == {}


class FakeNotifier:
    def __init__(self, ok=True):
        self.ok, self.calls = ok, []

    def find(self, tag):
        return iter([object()])

    def notify(self, **kw):
        self.calls.append(kw)

        return self.ok if kw["tag"] == "urgent" else True


def test_flush_sends_one_message_per_tier_and_rolls_back_failed_tier(tmp_path):
    found, counts = parse()
    state = State(tmp_path)

    state.record_scan(IMG, "img:1", [], counts, found)

    notifier = FakeNotifier(ok=False)  # urgent send fails, normal succeeds
    alerter = Alerter(Config(), notifier)

    alerter.add(ImageAlert(IMG, "img:1", [], True, found, dict.fromkeys(found)))
    alerter.flush(state)
    assert [c["tag"] for c in notifier.calls] == ["urgent", "normal"]

    urgent = notifier.calls[0]

    assert urgent["title"].startswith("🔴 URGENT: 2 new vulnerabilities")
    assert "· KEV · EPSS 100% · RCE" in urgent["body"]
    assert (
        "[CVE-2021-42013](https://nvd.nist.gov/vuln/detail/CVE-2021-42013)"
        in urgent["body"]
    )
    assert "| KEV: 1" in urgent["body"]
    assert "CVE-2021-39537" not in urgent["body"]
    assert state.alerted(IMG) == {PLAIN: "normal"}  # urgent ones un-marked for retry
    assert alerter.pending == []

    batch = state.last_batch["messages"]

    assert [m["tier"] for m in batch] == ["urgent", "normal"] and batch[0][
        "title"
    ] == urgent["title"]


def test_format_groups_packages_and_puts_important_first():
    new = {
        "a": Finding("CVE-1", "Critical", "curl", "8.1", "", ""),
        "b": Finding("CVE-1", "Critical", "libcurl4t64", "8.1", "", ""),
        "c": Finding("CVE-2", "High", "pip", "23", "24", "", cls="RCE"),
        "d": Finding(
            "GHSA-x",
            "Medium",
            "lodash",
            "4",
            "",
            "https://github.com/advisories/GHSA-x",
            kev=True,
        ),
    }
    title, body = Alerter(Config(), FakeNotifier()).format(
        [ImageAlert(IMG, "img:1", ["c1"], False, new)]
    )
    lines = body.splitlines()

    assert title == "3 new vulnerabilities (1 critical, 1 high, 1 medium) in 1 image"
    assert lines[1] == "Critical: 1 | High: 1 | Medium: 1 | RCE: 1 | KEV: 1"
    assert (
        lines[2]
        == "- [GHSA-x](https://github.com/advisories/GHSA-x) [Medium] lodash 4 · KEV"
    )
    assert (
        lines[3]
        == "- [CVE-2](https://nvd.nist.gov/vuln/detail/CVE-2) [High] pip 23 (fix: 24) · RCE"
    )
    assert (
        lines[4]
        == "- [CVE-1](https://nvd.nist.gov/vuln/detail/CVE-1) [Critical] curl, libcurl4t64 8.1"
    )


def test_default_routing_sends_urgent_to_main_urls():
    a = Alerter(Config(apprise_urls="json://localhost/a"))

    assert len(list(a.notifier.find("urgent"))) == 1

    b = Alerter(
        Config(
            apprise_urls="json://localhost/a", apprise_urls_urgent="json://localhost/b"
        )
    )

    assert len(list(b.notifier.find("urgent"))) == 1
    assert len(list(b.notifier.find("normal"))) == 1


def test_settings_override_env_and_bad_settings_are_ignored(tmp_path):
    env = Config(data_dir=tmp_path, apprise_urls="json://localhost/a")

    assert env.apply_settings(None) is env

    cfg = env.apply_settings(
        {
            "min_severity": "Critical",
            "epss_threshold": 0.5,
            "targets": [{"url": "json://localhost/b", "tiers": ["urgent"]}],
        }
    )

    assert (cfg.min_severity, cfg.epss_threshold) == ("critical", 0.5)

    a = Alerter(cfg)

    assert len(list(a.notifier.find("urgent"))) == 1 and not any(
        a.notifier.find("normal")
    )

    # emptied in the TUI, no fallback to env
    assert env.apply_settings({"targets": []}).routes() == []
    assert env.apply_settings({"min_severity": "bogus"}) is env
    assert env.apply_settings({"rescan_schedule": "bogus"}) is env
    assert env.apply_settings({"rescan_schedule": "*/5 * * * *"}).rescan_schedule == (
        "*/5 * * * *"
    )


def test_legacy_settings_file_is_imported_once(tmp_path):
    (tmp_path / "settings.json").write_text(json.dumps({"min_severity": "low"}))
    assert State(tmp_path).settings == {"min_severity": "low"}
    assert not (tmp_path / "settings.json").exists()
    assert (tmp_path / "settings.json.imported").exists()


def test_tui_saves_settings(tmp_path, monkeypatch):
    import asyncio

    from semaphore.tui import SemaphoreTUI, TargetRow

    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("APPRISE_URLS", "json://localhost/a")

    async def run():
        app = SemaphoreTUI()

        async with app.run_test() as pilot:
            assert len(app.query(TargetRow)) == 1  # pre-filled from env
            app.query_one("#epss").value = "0.3"
            app.query_one("#schedule").value = "nope"
            await pilot.press("ctrl+s")
            await pilot.pause()

            assert State(tmp_path, readonly=True).settings is None  # bad cron

            app.query_one("#schedule").value = "0 3 * * 1"
            await pilot.press("ctrl+s")
            await pilot.pause()

    asyncio.run(run())

    saved = State(tmp_path, readonly=True).settings

    assert saved == {
        "min_severity": "high",
        "epss_threshold": 0.3,
        "rescan_schedule": "0 3 * * 1",
        "targets": [{"url": "json://localhost/a", "tiers": ["urgent", "normal"]}],
    }


def test_daemon_reloads_settings_when_tui_changes_them(tmp_path):
    from semaphore.app import Semaphore

    sem = Semaphore(Config(data_dir=tmp_path))
    tui = State(tmp_path)

    assert sem.alerter.notifier is None

    tui.settings = {
        "min_severity": "low",
        "targets": [{"url": "json://localhost/a", "tiers": ["normal"]}],
    }

    tui.save()
    sem.reload_settings()
    assert sem.config.min_severity == "low" and any(sem.alerter.notifier.find("normal"))


def test_daemon_status_is_pushed_until_batch_ends(tmp_path):
    from semaphore.app import Semaphore

    sem = Semaphore(Config(data_dir=tmp_path))

    sem.mark_scanning(["a", "b"])
    sem.mark_scanning(["a"])
    sem.status("generating SBOM", "httpd:2.4.49")
    assert sem.bus.status["scanning"] == ["a", "b"]
    assert sem.bus.status["activity"]["stage"] == "generating SBOM"
    assert sem.bus.status["activity"]["left"] == 2
    sem.end_of_batch()
    assert sem.bus.status == {"scanning": [], "pending": [], "activity": None}
    assert not sem.scanning


def test_bus_pushes_status_and_queues_tui_requests(sock):
    from semaphore.bus import Bus

    tasks = queue.Queue()
    bus = Bus(sock, tasks)

    bus.start()

    with socket.socket(socket.AF_UNIX) as c:
        c.connect(str(sock))

        f = c.makefile("rb")

        def recv():
            return json.loads(f.readline())

        assert recv() == {"scanning": [], "pending": [], "activity": None}
        assert tasks.get(timeout=1) == ("hide_stopped",)
        bus.publish(scanning=["a"])
        assert recv()["scanning"] == ["a"]
        c.sendall(b'{"rescan": ["b"]}\n{"rescan": ["c"]}\n{"settings": true}\n')
        assert recv()["pending"] == ["b"]
        assert recv()["pending"] == ["b", "c"]

        # one discard for requests merged before it runs
        assert tasks.get(timeout=1) == ("discard",)
        assert tasks.get(timeout=1) == ("settings",)

        assert bus.take_pending() == ["b", "c"] and bus.status["pending"] == []
        c.sendall(b'{"rescan": null}\n')
        assert recv()["pending"] is None

        assert tasks.get(timeout=1) == ("discard",)


def test_tui_double_ctrl_c_quits(tmp_path, monkeypatch):
    import asyncio

    from semaphore.tui import SemaphoreTUI

    monkeypatch.setenv("DATA_DIR", str(tmp_path))

    async def run():
        app = SemaphoreTUI()

        async with app.run_test() as pilot:
            await pilot.press("ctrl+c")
            assert app.is_running
            app.query_one(
                "#epss"
            ).focus()  # inputs bind ctrl+c to copy, quitting must still win
            await pilot.press("ctrl+c")
            await pilot.pause()
            assert not app.is_running

    asyncio.run(run())


def test_newer_tag_stays_in_line_and_suffix():
    from semaphore.updates import newer_tag

    tags = [
        "1.27.2",
        "1.27.3",
        "1.27.10",
        "1.28.0",
        "1.27.11-alpine",
        "v1.27.12",
        "latest",
        "1.27",
    ]

    assert newer_tag("1.27.3", tags) == "1.27.10"  # numeric, not lexical; no 1.28 jump
    assert newer_tag("1.27.10", tags) is None
    assert newer_tag("1.27.3-alpine", tags) == "1.27.11-alpine"
    assert newer_tag("v1.27.3", tags) == "v1.27.12"
    assert (
        newer_tag("3.12-slim", ["3.13-slim", "3.14-slim", "4.0-slim", "3.14"])
        == "3.14-slim"
    )
    assert newer_tag("latest", tags) is None and newer_tag("3", ["4", "5"]) is None


def test_split_ref():
    from semaphore.updates import split_ref

    assert split_ref("nginx:1.27") == ("nginx", "1.27")
    assert split_ref("localhost:5000/app") == ("localhost:5000/app", "latest")
    assert split_ref("ghcr.io/a/b:v2") == ("ghcr.io/a/b", "v2")
    assert split_ref("nginx@sha256:abc") is None and split_ref("sha256:abc") is None


def candidate_without_kev():
    return {
        "matches": [
            m for m in SAMPLE["matches"] if m["vulnerability"]["id"] != "CVE-2021-42013"
        ]
    }


def test_update_check_scans_newer_tag_once_and_reports_fixes(tmp_path, monkeypatch):
    from semaphore import updates
    from semaphore.scan import Scanner

    calls = []

    def fake_run(cmd, timeout, **kw):
        calls.append(cmd[:2])

        if cmd[:2] == ["crane", "digest"]:
            return {"httpd:2.4.49": "sha256:old\n", "httpd:2.4.69": "sha256:new\n"}[
                cmd[2]
            ]

        if cmd[:2] == ["crane", "ls"]:
            return "2.4.48\n2.4.49\n2.4.69\n2.4.70-alpine\n2.5.0\nlatest\n"

        Path(cmd[-1].split("=", 1)[1]).write_text("{}")  # syft

        return ""

    monkeypatch.setattr(updates, "run_tool", fake_run)

    cfg = Config(data_dir=tmp_path)

    cfg.sbom_dir.mkdir()

    scanner = Scanner(cfg)
    scanner.match = lambda sbom, only_fixed: json.dumps(candidate_without_kev())
    checker = updates.UpdateChecker(cfg, scanner)
    found, _ = parse()
    refs = [
        "abc12",
        "httpd:2.4.49",
        "httpd@sha256:old",
        "abc123",
    ]  # short ID hint first, bare ID last
    u = checker.check("sha256:abc123", refs, found)

    assert (u["ref"], u["pull"], u["fixes"]) == (
        "httpd:2.4.69",
        "httpd@sha256:new",
        [KEV],
    )
    assert (
        u["counts"]
        == parse_matches(candidate_without_kev(), cfg.min_rank, cfg.epss_threshold)[1]
    )  # summary if the update is applied
    checker.check("sha256:abc123", refs, found)
    assert calls.count(["syft", "scan"]) == 1  # SBOM cached by digest
    assert (
        checker.check("sha256:abc123", ["abc123"], found) is None
    )  # local build, no registry calls


def test_update_shows_in_alert_and_notice_retries_until_sent(tmp_path):
    found, counts = parse()
    update = {
        "ref": "httpd:2.4.69",
        "pull": "httpd@sha256:new",
        "digest": "sha256:new",
        "fixes": [KEV],
        "checked": "now",
    }
    state = State(tmp_path)

    state.record_scan(IMG, "httpd:2.4.49", ["web"], counts, found, update)

    class FailingNotice(FakeNotifier):
        def notify(self, **kw):
            self.calls.append(kw)

            return self.ok or not kw["title"].startswith("⬆")

    for ok in (False, True):
        notifier = FailingNotice(ok=ok)
        alerter = Alerter(Config(), notifier)

        alerter.add(
            ImageAlert(
                IMG, "httpd:2.4.49", ["web"], True, found, dict.fromkeys(found), update
            )
        )
        alerter.add_update(IMG, "httpd:2.4.49", ["web"], update, found)
        alerter.flush(state)
        assert state.update(IMG)["notified"] == ("sha256:new" if ok else None)

    urgent, normal, notice = notifier.calls

    assert (
        "⬆ httpd:2.4.69 fixes 1/2" in urgent["body"]
        and "· KEV · EPSS 100% · RCE · ⬆ fixed" in urgent["body"]
    )
    assert "⬆" not in normal["body"]
    assert (
        notice["tag"] == "normal" and notice["title"] == "⬆ 1 fixing update available"
    )
    assert (
        notice["body"] == "**httpd:2.4.49** (web) → httpd:2.4.69: fixes 1/3 (1 urgent)"
    )
    state.record_scan(
        IMG, "httpd:2.4.49", ["web"], counts, found, update
    )  # rescan keeps the mark
    assert state.update(IMG)["notified"] == "sha256:new"
    state.write_summary()

    row = json.loads(state.summary_path.read_text())["images"][0]

    assert row["update"] == {"ref": "httpd:2.4.69", "fixes": 1}


def test_rescan_request_discards_and_rescans_running_images(tmp_path):
    from semaphore.app import Semaphore

    found, counts = parse()
    sem = Semaphore(Config(data_dir=tmp_path))
    running = {"sha256:run": {"containers": {"web"}, "refs": {"web:1"}}}
    rescanned = []

    class Host:
        def running_images(self):
            return running

    sem.host = Host()
    sem.scan_images = lambda images, *a: rescanned.extend(images)

    sem.config.sbom_dir.mkdir()

    sbom = sem.scanner.artifact(IMG, "syft.json")

    sbom.write_text("{}")
    sem.state.record_scan(IMG, "img:1", [], counts, found)
    sem.state.save()
    sem.bus.receive({"rescan": [IMG]})
    sem.handle(sem.tasks.get_nowait())
    assert IMG not in sem.state and not sbom.exists() and rescanned == []
    sem.state.record_scan(IMG, "img:1", [], counts, found)
    sem.bus.receive({"rescan": None})  # all: stored and running images
    sem.handle(sem.tasks.get_nowait())
    assert IMG not in sem.state and rescanned == ["sha256:run"]

    # a running image keeps its alert marks, only its SBOM goes
    run_sbom = sem.scanner.artifact("sha256:run", "syft.json")

    run_sbom.write_text("{}")
    sem.state.record_scan("sha256:run", "web:1", ["web"], counts, found)

    marks = sem.state.alerted("sha256:run")

    sem.bus.receive({"rescan": ["sha256:run"]})
    sem.handle(sem.tasks.get_nowait())
    assert "sha256:run" in sem.state and sem.state.alerted("sha256:run") == marks
    assert not run_sbom.exists() and rescanned == ["sha256:run"] * 2


def test_update_hides_old_version_and_keeps_its_alert_marks(tmp_path):
    from semaphore.app import Semaphore

    found, counts, rest = parse_matches(SAMPLE, Config().min_rank, 0.1)
    running = {"sha256:b": {"containers": {"web"}, "refs": {"web:b"}}}

    class Host:
        def running_images(self):
            return running

        def candidate_refs(self, image_id, hints):
            return list(hints)

    for only in (False, True):
        sem = Semaphore(Config(data_dir=tmp_path / str(only), only_running=only))
        sem.host = Host()
        sem.config.sbom_dir.mkdir(parents=True)

        for img in (IMG, "sha256:b"):  # A was scanned and alerted, B replaced it
            sem.commit((img, {}, [], img, True), (found, counts, rest, None))
            sem.scanner.artifact(img, "syft.json").write_text("{}")

        sem.alerter.pending.clear()
        marks = sem.state.alerted(IMG)
        sem.handle(("hide_stopped",))
        listed = [r["id"] for r in sem.state.rows()]
        assert listed == (["sha256:b"] if only else [IMG, "sha256:b"])
        assert IMG in sem.state and sem.state.alerted(IMG) == marks

    # A runs again (rollback, or compose starting it after destroying the old container): listed, not re-alerted
    running[IMG] = {"containers": {"web"}, "refs": {"web:a"}}
    job = sem.prepare(IMG, running[IMG], False)
    assert job is not None
    sem.commit(job, (found, counts, rest, None))
    assert IMG in [r["id"] for r in sem.state.rows()] and not sem.alerter.pending


def test_events_yield_start_image_and_destroy_marker():
    from semaphore.host import DockerHost

    class Containers:
        def get(self, cid):
            return type("C", (), {"attrs": {"Image": "sha256:new"}})()

    class Client:
        containers = Containers()

        def events(self, **kw):
            actor = {"ID": "c1", "Attributes": {"image": "web:2"}}

            return [
                {"Type": "container", "Action": "start", "Actor": actor},
                {"Type": "container", "Action": "destroy", "Actor": actor},
            ]

    got = list(DockerHost(Client()).events(["container"], ["start", "destroy"]))
    assert got == [("sha256:new", "web:2"), (None, None)]


def test_identical_rescan_sends_no_alert(tmp_path):
    from semaphore.app import Semaphore

    sem = Semaphore(Config(data_dir=tmp_path))
    found, counts, rest = parse_matches(SAMPLE, sem.config.min_rank, 0.1)
    info = {"containers": {"web"}}

    sem.commit((IMG, info, [], "img:1", True), (found, counts, rest, None))
    assert [a.is_new_image for a in sem.alerter.pending] == [True]
    sem.alerter.pending.clear()
    sem.commit((IMG, info, [], "img:1", True), (found, counts, rest, None))
    assert not sem.alerter.pending


def test_scan_images_analyzes_in_parallel_and_commits_on_worker(tmp_path):
    from semaphore.app import Semaphore

    sem = Semaphore(Config(data_dir=tmp_path, scan_workers=2))
    found, counts, rest = parse_matches(SAMPLE, sem.config.min_rank, 0.1)
    both = threading.Barrier(
        2, timeout=5
    )  # times out if the two analyses run one after the other
    committed = []

    class Host:
        def candidate_refs(self, img_id, hints):
            return [*hints, img_id]

    def analyze(img_id, *_):
        both.wait()

        return found, counts, rest, None

    def commit(job, result, real=sem.commit):
        committed.append(threading.current_thread())
        real(job, result)

    sem.host, sem.analyze, sem.commit = Host(), analyze, commit
    sem.scanner.ensure_db = lambda: None

    sem.scan_images(
        {
            "sha256:a": {"containers": {"a"}, "refs": {"a:1"}},
            "sha256:b": {"containers": {"b"}, "refs": {"b:1"}},
        }
    )
    assert "sha256:a" in sem.state and "sha256:b" in sem.state
    assert committed == [threading.current_thread()] * 2 and not sem.scanning
    assert sem.alerter.pending


def test_tui_lists_images_and_requests_rescan_after_confirm(
    tmp_path, monkeypatch, sock
):
    import asyncio

    from semaphore.bus import Bus
    from semaphore.tui import Confirm, Findings, SemaphoreTUI

    monkeypatch.setenv("DATA_DIR", str(tmp_path))

    found, counts = parse()
    state = State(tmp_path)
    update = {
        "ref": "httpd:2.4.69",
        "pull": "httpd@sha256:new",
        "digest": "sha256:new",
        "fixes": [KEV],
        "checked": "now",
        "counts": {"High": 2, "Medium": 1},
    }

    state.record_scan(IMG, "httpd:2.4.49", ["web"], counts, found, update)
    state.save()

    tasks = queue.Queue()
    bus = Bus(sock, tasks)

    bus.start()

    async def run():
        app = SemaphoreTUI()

        async with app.run_test() as pilot:
            await until(pilot, lambda: app.daemon is not None)
            assert str(app.query_one("#status").content) == "Idle"

            assert tasks.get(timeout=1) == ("hide_stopped",)  # queued on connect
            assert tasks.get(timeout=1) == ("settings",)  # sent on connect
            table = app.query_one("#image-table")
            row = table.get_row(IMG)

            assert row[1] == "httpd:2.4.49" and row[3].startswith("C:")
            assert row[4] == "httpd:2.4.69 (fixes 1)" and row[5] == "H:2 | M:1"
            app.query_one("TabbedContent").active = "images"
            await pilot.pause()
            table.focus()
            await pilot.press("space")  # tick the row
            assert app.selected == {IMG}
            await pilot.press("enter")  # CVE dialog
            await pilot.pause()
            assert isinstance(app.screen, Findings)

            cves = app.screen.query_one("DataTable").get_column_at(0)

            assert any("(fixed in httpd:2.4.69)" in str(c) for c in cves)
            await pilot.press("escape")
            await pilot.pause()
            assert app.selected == {IMG}
            app.rescan_selected()
            await pilot.pause()
            assert isinstance(app.screen, Confirm)
            await pilot.press("enter")  # Cancel has focus
            await pilot.pause()
            assert tasks.empty()
            app.rescan_selected()
            await pilot.pause()
            await pilot.click("#yes")

            # spinner + yellow row until the daemon is done
            await until(pilot, lambda: app.scanning == {IMG})
            assert table.get_row(IMG)[1].endswith(" httpd:2.4.49")

    asyncio.run(run())
    assert tasks.get_nowait() == ("discard",) and bus.status["pending"] == [IMG]


def test_tui_without_daemon_says_so_and_refuses_rescans(tmp_path, monkeypatch, sock):
    import asyncio

    from semaphore.tui import SemaphoreTUI

    monkeypatch.setenv("DATA_DIR", str(tmp_path))

    async def run():
        app = SemaphoreTUI()

        async with app.run_test() as pilot:
            await pilot.pause()
            assert str(app.query_one("#status").content) == "Daemon not running"
            app.request_rescan(None)
            await pilot.pause()
            assert not app.scanning

    asyncio.run(run())


def test_next_rescan_follows_cron_in_local_time():
    cfg = Config()  # default: daily at midnight
    after = datetime(2026, 1, 1, 15, 0).timestamp()

    assert cfg.next_rescan(after) == datetime(2026, 1, 2).timestamp()
    assert (
        Config(rescan_schedule="30 */6 * * *").next_rescan(after)
        == datetime(2026, 1, 1, 18, 30).timestamp()
    )

    with pytest.raises(SystemExit):
        Config(rescan_schedule="nope")


def test_tui_keeps_discarded_row_until_its_new_scan_lands(tmp_path, monkeypatch, sock):
    import asyncio

    from semaphore.bus import Bus
    from semaphore.tui import SemaphoreTUI

    monkeypatch.setenv("DATA_DIR", str(tmp_path))

    found, counts = parse()
    daemon = State(tmp_path)

    daemon.record_scan(IMG, "httpd:2.4.49", ["web"], counts, found, None)
    daemon.save()

    bus = Bus(sock, queue.Queue())

    bus.start()

    async def run():
        app = SemaphoreTUI()

        async with app.run_test() as pilot:
            table = app.query_one("#image-table")
            status = app.query_one("#status")

            await until(pilot, lambda: app.daemon is not None)
            app.request_rescan([IMG])
            await until(pilot, lambda: IMG in app.scanning)
            bus.take_pending()  # what Semaphore.discard does, then mark_scanning + forget
            daemon.forget(IMG)
            daemon.save()
            bus.publish(
                scanning=[IMG],
                activity={
                    "stage": "generating SBOM",
                    "image": "httpd:2.4.49",
                    "since": time.time(),
                    "left": 1,
                },
            )
            await until(pilot, lambda: "generating SBOM" in str(status.content))
            assert table.get_row(IMG)[1].endswith("httpd:2.4.49")  # old row, spinning
            assert IMG in app.scanning
            assert str(status.content)[2:] == "httpd:2.4.49 · generating SBOM · 0s"
            daemon.record_scan(IMG, "httpd:2.4.49", ["web"], {}, {}, None)
            daemon.save()
            bus.publish(scanning=[], activity=None)
            await until(pilot, lambda: IMG not in app.scanning)
            assert table.get_row(IMG)[3] == "clean"  # new scan
            assert str(status.content) == "Idle"
            daemon.forget(IMG)  # gone for good once nothing scans it
            daemon.save()
            bus.publish()
            await until(pilot, lambda: table.row_count == 0)

    asyncio.run(run())
