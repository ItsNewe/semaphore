import json
from pathlib import Path

from semaphore.alerts import Alerter, ImageAlert
from semaphore.config import Config
from semaphore.scan import parse_matches
from semaphore.store import State

SAMPLE = json.loads((Path(__file__).parent / "grype_sample.json").read_text())


def test_parse_matches_filters_by_severity():
    found, counts = parse_matches(SAMPLE, Config().min_rank)
    assert counts == {"Critical": 1, "High": 2, "Medium": 2}
    assert {f.id for f in found.values()} == {"CVE-2021-42013", "CVE-2023-50387", "CVE-2021-39537"}


def test_state_round_trip_and_rollback(tmp_path):
    found, counts = parse_matches(SAMPLE, Config().min_rank)
    s = State(tmp_path)
    s.record_scan("sha256:abc", "img:1", ["c1"], counts, found)
    s.last_rescan = 123.0
    s.save()

    s2 = State(tmp_path)
    s2.load()
    assert s2.alerted("sha256:abc") == set(found)
    assert s2.last_rescan == 123.0
    key = next(iter(found))
    s2.rollback("sha256:abc", [key])
    assert key not in s2.alerted("sha256:abc")


class FakeNotifier:
    def __init__(self, ok=True):
        self.ok, self.calls = ok, []

    def notify(self, **kw):
        self.calls.append(kw)
        return self.ok


def test_failed_notification_rolls_back(tmp_path):
    found, counts = parse_matches(SAMPLE, Config().min_rank)
    state = State(tmp_path)
    state.record_scan("sha256:abc", "img:1", [], counts, found)
    notifier = FakeNotifier(ok=False)
    alerter = Alerter(Config(), notifier)
    alerter.add(ImageAlert("sha256:abc", "img:1", [], True, found))
    alerter.flush(state)
    assert len(notifier.calls) == 1
    assert "3 new vulnerabilities" in notifier.calls[0]["title"]
    assert state.alerted("sha256:abc") == set()
    assert alerter.pending == []
